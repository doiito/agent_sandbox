use super::*;

pub(super) const FRAME_LIMIT: usize = 96 * 1024;
pub(super) const KERNEL_PROTOCOL: &str = "osv-code-kernel/v2";

pub(super) fn id(value: &str) -> bool {
    value.len() == 24
        && value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

pub(super) fn environment(values: &BTreeMap<String, String>) -> Result<()> {
    if values.len() > 64
        || values.iter().any(|(k, v)| {
            k.is_empty()
                || k.len() > 64
                || v.len() > 8192
                || v.contains('\0')
                || !k.bytes().enumerate().all(|(i, b)| {
                    b == b'_' || b.is_ascii_alphabetic() || i > 0 && b.is_ascii_digit()
                })
        })
        || values.iter().map(|(k, v)| k.len() + v.len()).sum::<usize>() > 16 * 1024
    {
        return Err(Error::new("invalid_request", "invalid code environment"));
    }
    Ok(())
}

pub(super) fn validate_request(request: &Request) -> Result<()> {
    let context = match request {
        Request::Create {
            context_id, cwd, ..
        } => {
            if cwd.len() > 1024 || !cwd.starts_with('/') || cwd.chars().any(char::is_control) {
                return Err(Error::new("invalid_request", "invalid context cwd"));
            }
            Some(context_id)
        }
        Request::Info { context_id }
        | Request::Restart { context_id, .. }
        | Request::Remove { context_id, .. } => Some(context_id),
        Request::Execute {
            context_id,
            execution_id,
            code,
            environment: env,
            timeout_ms,
            ..
        } => {
            if !id(execution_id)
                || code.len() > 64 * 1024
                || code.contains('\0')
                || *timeout_ms > 300_000
            {
                return Err(Error::new("invalid_request", "invalid code execution"));
            }
            environment(env)?;
            if serde_json::to_vec(&serde_json::json!({"code":code,"env":env}))
                .map_err(|_| Error::new("invalid_request", "invalid code JSON"))?
                .len()
                > FRAME_LIMIT
            {
                return Err(Error::new(
                    "invalid_request",
                    "encoded code frame exceeds limit",
                ));
            }
            Some(context_id)
        }
        Request::Cancel {
            context_id,
            execution_id,
            ..
        } => {
            if !id(execution_id) {
                return Err(Error::new("invalid_request", "invalid execution ID"));
            }
            Some(context_id)
        }
        Request::Execution { execution_id, .. } => {
            if !id(execution_id) {
                return Err(Error::new("invalid_request", "invalid execution ID"));
            }
            None
        }
        Request::Default { .. } | Request::List {} => None,
    };
    if context.is_some_and(|value| !id(value)) {
        return Err(Error::new("invalid_request", "invalid context ID"));
    }
    Ok(())
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum EvalState {
    Evaluating,
    EventLoop,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Frame {
    Ready {
        protocol: String,
        language: Language,
        version: String,
    },
    Result {
        data: BTreeMap<String, Value>,
        is_main_result: bool,
        execution_count: u64,
    },
    Error {
        name: String,
        value: String,
        traceback: String,
        execution_count: u64,
    },
    Done {
        execution_count: u64,
    },
    InterruptAck {
        execution_count: u64,
    },
    ExecutionState {
        execution_count: u64,
        state: EvalState,
    },
}
fn bounded_json(value: &Value, depth: usize) -> bool {
    if depth > 16 {
        return false;
    }
    match value {
        Value::String(s) => s.len() <= 32 * 1024,
        Value::Array(a) => a.len() <= 1024 && a.iter().all(|v| bounded_json(v, depth + 1)),
        Value::Object(o) => {
            o.len() <= 1024
                && o.iter()
                    .all(|(k, v)| k.len() <= 1024 && bounded_json(v, depth + 1))
        }
        _ => true,
    }
}
impl Frame {
    pub(super) fn late_output_size(&self, finished_count: u64) -> Option<usize> {
        match self {
            Self::Result {
                data,
                execution_count,
                ..
            } if *execution_count > 0 && *execution_count <= finished_count => {
                Some(serde_json::to_vec(data).unwrap().len())
            }
            Self::Error {
                name,
                value,
                traceback,
                execution_count,
            } if *execution_count > 0 && *execution_count <= finished_count => {
                Some(name.len() + value.len() + traceback.len())
            }
            _ => None,
        }
    }
    pub(super) fn parse(data: &[u8]) -> Result<Self> {
        if data.is_empty() || data.len() > FRAME_LIMIT {
            return Err(Error::new("kernel_protocol", "invalid language frame size"));
        }
        let frame: Self = serde_json::from_slice(data)
            .map_err(|_| Error::new("kernel_protocol", "invalid language frame"))?;
        let valid = match &frame {
            Self::Ready {
                protocol, version, ..
            } => protocol.len() <= 64 && version.len() <= 64,
            Self::Result {
                data,
                execution_count,
                ..
            } => {
                *execution_count > 0
                    && !data.is_empty()
                    && data.len() <= 16
                    && data.iter().all(|(k, v)| {
                        k.len() <= 128
                            && k.contains('/')
                            && bounded_json(v, 0)
                            && (k == "application/json" || v.is_string())
                    })
            }
            Self::Error {
                name,
                value,
                traceback,
                execution_count,
            } => {
                *execution_count > 0
                    && !name.is_empty()
                    && name.len() <= 512
                    && value.len() <= 16 * 1024
                    && traceback.len() <= 32 * 1024
            }
            Self::Done { execution_count }
            | Self::InterruptAck { execution_count }
            | Self::ExecutionState {
                execution_count, ..
            } => *execution_count > 0,
        };
        if !valid {
            return Err(Error::new(
                "kernel_protocol",
                "language frame fields exceed limits",
            ));
        }
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn only_completed_result_or_error_can_be_discarded_as_late() {
        let result = Frame::parse(br#"{"type":"result","data":{"text/plain":"late"},"is_main_result":false,"execution_count":2}"#).unwrap();
        assert!(result.late_output_size(1).is_none());
        assert!(result.late_output_size(2).is_some());
        assert!(result.late_output_size(3).is_some());
        let error = Frame::parse(br#"{"type":"error","name":"Error","value":"late","traceback":"trace","execution_count":1}"#).unwrap();
        assert_eq!(error.late_output_size(1), Some(14));
        for input in [
            r#"{"type":"done","execution_count":1}"#,
            r#"{"type":"interrupt_ack","execution_count":1}"#,
            r#"{"type":"execution_state","execution_count":1,"state":"event_loop"}"#,
            r#"{"type":"ready","protocol":"osv-code-kernel/v2","language":"python","version":"3.12.16"}"#,
        ] {
            assert!(
                Frame::parse(input.as_bytes())
                    .unwrap()
                    .late_output_size(2)
                    .is_none()
            );
        }
        assert!(
            Frame::parse(br#"{"type":"ready","language":"python","version":"3.12.16"}"#).is_err()
        );
    }
    #[test]
    fn encoded_source_and_environment_are_bounded_before_admission() {
        let mut r = Request::Execute {
            context_id: "0".repeat(24),
            generation: 1,
            execution_id: "1".repeat(24),
            code: "x".repeat(65536),
            environment: BTreeMap::new(),
            timeout_ms: 0,
        };
        assert!(validate_request(&r).is_ok());
        if let Request::Execute { code, .. } = &mut r {
            *code = "\n".repeat(65536);
        }
        assert!(validate_request(&r).is_err());
        assert!(environment(&BTreeMap::from([("LD_PRELOAD\0".into(), "bad".into())])).is_err());
    }
    #[test]
    fn rejects_unknown_frames_fields_nested_json_and_wrong_mime_types() {
        for input in [
            r#"{"type":"done","execution_count":0}"#,
            r#"{"type":"done","execution_count":1,"extra":1}"#,
            r#"{"type":"result","data":{"text/html":42},"is_main_result":false,"execution_count":1}"#,
        ] {
            assert!(Frame::parse(input.as_bytes()).is_err());
        }
        let mut v = serde_json::json!(42);
        for _ in 0..18 {
            v = serde_json::json!([v]);
        }
        let data=serde_json::to_vec(&serde_json::json!({"type":"result","data":{"application/json":v},"is_main_result":true,"execution_count":1})).unwrap();
        assert!(Frame::parse(&data).is_err());
        assert!(Frame::parse(br#"{"type":"result","data":{"application/json":{"value":42}},"is_main_result":true,"execution_count":1}"#).is_ok());
    }
    #[test]
    fn terminal_event_retains_reserved_slot_and_eviction_is_explicit() {
        let mut record = Record {
            id: "1".repeat(24),
            context_id: "0".repeat(24),
            generation: 1,
            status: ExecutionStatus::Running,
            events: vec![],
            sequence: 0,
            bytes: 0,
            evicted: false,
            failure: None,
        };
        for _ in 0..EVENT_LIMIT - 1 {
            record.push(Event::Started, 0).unwrap();
        }
        assert!(record.push(Event::Started, 0).is_err());
        record.finish(ExecutionStatus::Failed, false);
        assert_eq!(record.events.len(), EVENT_LIMIT);
        record.events.clear();
        record.evicted = true;
        assert!(record.page(0).unwrap().events_evicted);
        assert!(!record.page(record.sequence).unwrap().events_evicted);
    }
}
