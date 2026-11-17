use super::*;
use std::io::{Read, Write};

fn ready(file: &File, control: &Control, events: i16, deadline: Instant) -> io::Result<()> {
    loop {
        if control.stop.load(Ordering::Acquire) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let mut fd = libc::pollfd {
            fd: file.as_raw_fd(),
            events,
            revents: 0,
        };
        let result = unsafe {
            libc::poll(
                &mut fd,
                1,
                remaining.min(IO_SLICE).as_millis().max(1) as i32,
            )
        };
        if result > 0 {
            return Ok(());
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }
}
fn request(file: &mut File, control: &Control) -> io::Result<Request> {
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut bytes = Vec::new();
    loop {
        ready(file, control, libc::POLLIN, deadline)?;
        let mut part = [0u8; 4096];
        match file.read(&mut part) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => bytes.extend_from_slice(&part[..count]),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        }
        if bytes.len() > wire::REQUEST_LIMIT {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if let Some(end) = bytes.iter().position(|b| *b == b'\n') {
            if end + 1 != bytes.len() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            return Request::parse(&bytes);
        }
    }
}
pub(super) fn serve(mut file: File, control: &Control) {
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return;
    }
    let Ok(request) = request(&mut file, control) else {
        return;
    };
    let response = control.dispatch(&request);
    let Ok(bytes) = wire::encode(request, response) else {
        return;
    };
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut offset = 0;
    while offset < bytes.len() {
        if ready(&file, control, libc::POLLOUT, deadline).is_err() {
            return;
        }
        match file.write(&bytes[offset..]) {
            Ok(0) => return,
            Ok(count) => offset += count,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                ) =>
            {
                continue;
            }
            Err(_) => return,
        }
    }
}
