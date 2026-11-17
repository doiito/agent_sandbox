use super::*;
use serde::{Deserialize, Serialize};

pub const PROTOCOL: &str = "fc-code/v1";
pub const PREFIX: &str = "FC_CODE_REPLY ";
pub(super) const REQUEST_LIMIT: usize = 128 * 1024;
pub(super) const REPLY_LIMIT: usize = 256 * 1024;

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
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub protocol: String,
    pub session_id: String,
    pub nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<Binding>,
    pub request: code::Request,
}
impl Request {
    pub(super) fn parse(bytes: &[u8]) -> io::Result<Self> {
        if bytes.is_empty() || bytes.len() > REQUEST_LIMIT {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let request: Self =
            serde_json::from_slice(bytes).map_err(|_| io::ErrorKind::InvalidData)?;
        if request.protocol != PROTOCOL
            || !hex(&request.session_id, 24)
            || !hex(&request.nonce, 64)
            || request
                .binding
                .as_ref()
                .is_some_and(|binding| !binding.valid())
        {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(request)
    }
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Reply {
    pub protocol: String,
    pub session_id: String,
    pub nonce: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<Binding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response: Option<Response>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<code::Error>,
}
pub(super) fn encode(request: Request, result: code::Result<Response>) -> io::Result<Vec<u8>> {
    let (response, error) = match result {
        Ok(response) => (Some(response), None),
        Err(error) => (None, Some(error)),
    };
    let reply = Reply {
        protocol: PROTOCOL.into(),
        session_id: request.session_id,
        nonce: request.nonce,
        binding: request.binding,
        response,
        error,
    };
    let mut frame = PREFIX.as_bytes().to_vec();
    serde_json::to_writer(&mut frame, &reply)?;
    frame.push(b'\n');
    if frame.len() > REPLY_LIMIT {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(frame)
}
pub(super) fn error(code: &str, message: &str) -> code::Error {
    code::Error {
        code: code.into(),
        message: message.into(),
    }
}
fn hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
