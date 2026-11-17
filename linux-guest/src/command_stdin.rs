//! One bounded, nonblocking stdin delivery; command control never waits on a pipe.
use crate::pristine::Binding;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::process::ChildStdin;

pub(super) const CHUNK_LIMIT: usize = 16 * 1024;
pub(super) const BYTE_LIMIT: usize = 1024 * 1024;
pub(super) const REQUEST_LIMIT: u32 = 256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InputFrame {
    protocol: String,
    job_id: String,
    #[serde(default)]
    binding: Option<Binding>,
    sequence: u32,
    data_base64: String,
    close: bool,
}
struct Pending {
    sequence: u32,
    data: Vec<u8>,
    written: usize,
    close: bool,
}
pub(super) struct InputAck {
    pub sequence: u32,
    pub written_bytes: usize,
    pub closed: bool,
    pub error_code: Option<&'static str>,
}
pub(super) struct StdinState {
    enabled: bool,
    pipe: Option<ChildStdin>,
    pending: Option<Pending>,
    next: u32,
    bytes: usize,
}
impl StdinState {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            pipe: None,
            pending: None,
            next: 1,
            bytes: 0,
        }
    }
    pub fn attach(&mut self, pipe: Option<ChildStdin>) -> io::Result<()> {
        if let Some(pipe) = pipe.as_ref() {
            crate::set_nonblocking(pipe.as_raw_fd())?;
        }
        self.pipe = pipe;
        Ok(())
    }
    pub fn accept(
        &mut self,
        data: &[u8],
        protocol: &str,
        job: &str,
        binding: &Option<Binding>,
    ) -> io::Result<()> {
        let invalid =
            || io::Error::new(io::ErrorKind::InvalidData, "invalid command stdin control");
        let frame: InputFrame = serde_json::from_slice(data).map_err(|_| invalid())?;
        if !self.enabled
            || self.pending.is_some()
            || frame.protocol != protocol
            || frame.job_id != job
            || &frame.binding != binding
            || frame.sequence != self.next
            || self.next > REQUEST_LIMIT
            || frame.data_base64.len() > CHUNK_LIMIT.div_ceil(3) * 4
        {
            return Err(invalid());
        }
        let data = STANDARD.decode(&frame.data_base64).map_err(|_| invalid())?;
        if data.len() > CHUNK_LIMIT
            || STANDARD.encode(&data) != frame.data_base64
            || self.bytes + data.len() > BYTE_LIMIT
            || frame.close && !data.is_empty()
        {
            return Err(invalid());
        }
        self.bytes += data.len();
        self.next += 1;
        self.pending = Some(Pending {
            sequence: frame.sequence,
            data,
            written: 0,
            close: frame.close,
        });
        Ok(())
    }
    pub fn progress(&mut self) -> Option<InputAck> {
        let mut pending = self.pending.take()?;
        let mut error_code = None;
        if pending.close {
            self.pipe = None;
        } else if let Some(pipe) = self.pipe.as_mut() {
            while pending.written < pending.data.len() {
                match pipe.write(&pending.data[pending.written..]) {
                    Ok(0) => {
                        error_code = Some("stdin_io");
                        break;
                    }
                    Ok(n) => pending.written += n,
                    Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        self.pending = Some(pending);
                        return None;
                    }
                    Err(error) => {
                        error_code = Some(if error.kind() == io::ErrorKind::BrokenPipe {
                            "stdin_closed"
                        } else {
                            "stdin_io"
                        });
                        break;
                    }
                }
            }
            if error_code.is_some() {
                self.pipe = None;
            }
        } else {
            error_code = Some("stdin_closed");
        }
        Some(InputAck {
            sequence: pending.sequence,
            written_bytes: pending.written,
            closed: self.pipe.is_none(),
            error_code,
        })
    }
    pub fn finish(&mut self) -> Option<InputAck> {
        self.pipe = None;
        self.pending.take().map(|pending| InputAck {
            sequence: pending.sequence,
            written_bytes: pending.written,
            closed: true,
            error_code: Some("command_exited"),
        })
    }
}
