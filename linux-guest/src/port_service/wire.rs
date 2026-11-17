use serde::{Deserialize, Serialize};

pub const PROTOCOL: &str = "fc-port/v1";
pub const MAX_HANDSHAKE: usize = 4096;
pub const MAX_DATA: usize = 16 * 1024;
pub const MAX_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_DURATION_MS: u64 = 300_000;
pub const DATA: u8 = 1;
pub const EOF: u8 = 2;
pub const CANCEL: u8 = 3;
pub const FINISHED: u8 = 4;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub session_id: String,
    pub nonce: String,
}
impl Binding {
    pub fn valid(&self) -> bool {
        hex(&self.session_id, 24) && hex(&self.nonce, 64)
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    pub max_bytes: u64,
    pub timeout_ms: u64,
    pub idle_timeout_ms: u64,
}
impl Limits {
    fn valid(self) -> bool {
        (1..=MAX_BYTES).contains(&self.max_bytes)
            && (1..=MAX_DURATION_MS).contains(&self.timeout_ms)
            && (1..=MAX_DURATION_MS).contains(&self.idle_timeout_ms)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol: String,
    pub session_id: String,
    pub nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<Binding>,
    pub operation: String,
    pub id: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limits: Option<Limits>,
}
impl Request {
    pub fn parse(bytes: &[u8]) -> Result<Self, &'static str> {
        if bytes.is_empty() || bytes.len() > MAX_HANDSHAKE {
            return Err("invalid_request");
        }
        let r: Self = serde_json::from_slice(bytes).map_err(|_| "invalid_request")?;
        if r.protocol != PROTOCOL
            || !hex(&r.session_id, 24)
            || !hex(&r.nonce, 64)
            || !hex(&r.id, 24)
            || r.port == 0
            || r.binding
                .as_ref()
                .is_some_and(|b| !b.valid() || b.session_id != r.session_id)
            || match r.operation.as_str() {
                "open" => r.limits.is_none_or(|v| !v.valid()),
                "cancel" | "info" => r.limits.is_some(),
                _ => true,
            }
        {
            return Err("invalid_request");
        }
        Ok(r)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Info {
    pub id: String,
    pub port: u16,
    pub status: String,
    pub sent_bytes: u64,
    pub received_bytes: u64,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub protocol: String,
    pub session_id: String,
    pub nonce: String,
    pub binding: Option<Binding>,
    pub id: String,
    pub port: u16,
    pub response: Option<Info>,
    pub error: Option<String>,
}
impl Reply {
    pub(super) fn new(r: &Request, result: Result<Info, &'static str>) -> Self {
        let (response, error) = match result {
            Ok(value) => (Some(value), None),
            Err(value) => (None, Some(value.into())),
        };
        Self {
            protocol: PROTOCOL.into(),
            session_id: r.session_id.clone(),
            nonce: r.nonce.clone(),
            binding: r.binding.clone(),
            id: r.id.clone(),
            port: r.port,
            response,
            error,
        }
    }
}

pub(super) fn hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(5 + payload.len());
    bytes.push(kind);
    bytes.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    bytes.extend_from_slice(payload);
    bytes
}
