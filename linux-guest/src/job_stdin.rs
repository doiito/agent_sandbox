//! Fixed job stdin shares the nonblocking output/deadline supervisor.
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::io::{self, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::process::ChildStdin;

pub(super) const LIMIT: usize = 16 * 1024;

pub(super) fn decode(encoded: &str) -> io::Result<Vec<u8>> {
    let invalid = || io::Error::new(io::ErrorKind::InvalidData, "invalid bounded job stdin");
    if encoded.len() > LIMIT.div_ceil(3) * 4 {
        return Err(invalid());
    }
    let data = STANDARD.decode(encoded).map_err(|_| invalid())?;
    if data.len() > LIMIT || STANDARD.encode(&data) != encoded {
        return Err(invalid());
    }
    Ok(data)
}

pub(super) struct FixedInput {
    pipe: Option<ChildStdin>,
    data: Vec<u8>,
    written: usize,
}
impl FixedInput {
    pub fn new(pipe: ChildStdin, data: Vec<u8>) -> io::Result<Self> {
        crate::set_nonblocking(pipe.as_raw_fd())?;
        Ok(Self {
            pipe: if data.is_empty() { None } else { Some(pipe) },
            data,
            written: 0,
        })
    }
    pub fn fd(&self) -> RawFd {
        self.pipe.as_ref().map_or(-1, AsRawFd::as_raw_fd)
    }
    pub fn progress(&mut self) -> io::Result<()> {
        let Some(pipe) = self.pipe.as_mut() else {
            return Ok(());
        };
        while self.written < self.data.len() {
            match pipe.write(&self.data[self.written..]) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "job stdin")),
                Ok(count) => self.written += count,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::BrokenPipe => {
                    // Programs may deliberately ignore some or all supplied input.
                    self.pipe = None;
                    return Ok(());
                }
                Err(error) => return Err(error),
            }
        }
        self.pipe = None;
        Ok(())
    }
}
