use super::*;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, SocketAddrV4, TcpStream};

fn nonblocking(file: &File) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
fn ready(file: &File, control: &Control, events: i16, deadline: Instant) -> io::Result<()> {
    loop {
        if control.stop.load(Ordering::Acquire) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let until = deadline.min(control.deadline());
        if Instant::now() >= until {
            return Err(io::ErrorKind::TimedOut.into());
        }
        let mut poll = libc::pollfd {
            fd: file.as_raw_fd(),
            events,
            revents: 0,
        };
        let wait = until
            .saturating_duration_since(Instant::now())
            .min(SLICE)
            .as_millis()
            .max(1) as i32;
        let result = unsafe { libc::poll(&mut poll, 1, wait) };
        if result > 0 {
            return Ok(());
        }
        if result < 0 && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
            return Err(io::Error::last_os_error());
        }
    }
}
fn read_exact(
    file: &mut File,
    control: &Control,
    mut bytes: &mut [u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        ready(file, control, libc::POLLIN, deadline)?;
        match file.read(bytes) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => bytes = &mut bytes[count..],
            Err(e) if retry(&e) => (),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn write_all(
    file: &mut File,
    control: &Control,
    mut bytes: &[u8],
    deadline: Instant,
) -> io::Result<()> {
    while !bytes.is_empty() {
        ready(file, control, libc::POLLOUT, deadline)?;
        match file.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => bytes = &bytes[count..],
            Err(e) if retry(&e) => (),
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
fn json_reply(
    file: &mut File,
    value: &wire::Reply,
    control: &Control,
    deadline: Instant,
) -> io::Result<()> {
    let bytes = serde_json::to_vec(value)?;
    if bytes.len() > wire::MAX_HANDSHAKE {
        return Err(io::ErrorKind::InvalidData.into());
    }
    write_all(file, control, &(bytes.len() as u32).to_be_bytes(), deadline)?;
    write_all(file, control, &bytes, deadline)
}
pub(super) fn reply(
    file: &mut File,
    r: &Request,
    value: Result<Info, &'static str>,
    control: &Control,
) -> io::Result<()> {
    json_reply(
        file,
        &wire::Reply::new(r, value),
        control,
        Instant::now() + HANDSHAKE_TIMEOUT,
    )
}
pub(super) fn control(mut file: File, shared: Arc<Control>) {
    let request = (|| -> io::Result<Request> {
        nonblocking(&file)?;
        let deadline = Instant::now() + HANDSHAKE_TIMEOUT;
        let mut size = [0; 4];
        read_exact(&mut file, &shared, &mut size, deadline)?;
        let size = u32::from_be_bytes(size) as usize;
        if size == 0 || size > wire::MAX_HANDSHAKE {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut bytes = vec![0; size];
        read_exact(&mut file, &shared, &mut bytes, deadline)?;
        Request::parse(&bytes).map_err(|_| io::ErrorKind::InvalidData.into())
    })();
    let Ok(r) = request else {
        return;
    };
    if r.operation == "open" {
        shared.open(file, r);
    } else {
        let _ = reply(&mut file, &r, shared.inspect(&r), &shared);
    }
}

fn retry(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}
pub(super) fn open(
    mut host: File,
    request: Request,
    flow: Arc<Flow>,
    shared: Arc<Control>,
    lease: Instant,
) {
    let limits = request.limits.unwrap();
    let deadline = (Instant::now() + Duration::from_millis(limits.timeout_ms)).min(lease);
    let attempt = (|| -> Result<TcpStream, &'static str> {
        if flow.cancel.load(Ordering::Acquire) {
            return Err("cancelled");
        }
        if shared.stop.load(Ordering::Acquire) {
            return Err("service_closed");
        }
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .min(Duration::from_millis(250));
        if remaining.is_zero() {
            return Err("timeout");
        }
        // No caller-provided address, DNS, host route or external NIC is used.
        let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, request.port));
        let stream =
            TcpStream::connect_timeout(&address, remaining).map_err(|e| match e.kind() {
                io::ErrorKind::ConnectionRefused => "connection_refused",
                io::ErrorKind::TimedOut => "timeout",
                _ => "io_error",
            })?;
        stream.set_nonblocking(true).map_err(|_| "io_error")?;
        stream.set_nodelay(true).map_err(|_| "io_error")?;
        for option in [libc::SO_SNDBUF, libc::SO_RCVBUF] {
            if unsafe {
                libc::setsockopt(
                    stream.as_raw_fd(),
                    libc::SOL_SOCKET,
                    option,
                    (&TCP_BUFFER_BYTES as *const libc::c_int).cast(),
                    std::mem::size_of_val(&TCP_BUFFER_BYTES) as libc::socklen_t,
                )
            } < 0
            {
                return Err("io_error");
            }
        }
        Ok(stream)
    })();
    let mut tcp = match attempt {
        Ok(stream) => stream,
        Err(error) => {
            flow.finish(Some(error));
            let _ = reply(&mut host, &request, Err(error), &shared);
            return;
        }
    };
    let cancelled = if shared.stop.load(Ordering::Acquire) {
        Some("service_closed")
    } else if flow.cancel.load(Ordering::Acquire) {
        Some("cancelled")
    } else if Instant::now() >= deadline {
        Some("timeout")
    } else {
        None
    };
    if let Some(error) = cancelled {
        let _ = tcp.shutdown(Shutdown::Both);
        drop(tcp);
        flow.finish(Some(error));
        let _ = reply(&mut host, &request, Err(error), &shared);
        return;
    }
    flow.started.store(true, Ordering::Release);
    if json_reply(
        &mut host,
        &wire::Reply::new(&request, Ok(flow.info())),
        &shared,
        deadline.min(Instant::now() + HANDSHAKE_TIMEOUT),
    )
    .is_err()
    {
        let _ = tcp.shutdown(Shutdown::Both);
        drop(tcp);
        flow.finish(Some("connection_lost"));
        return;
    }
    let mut frame_boundary = true;
    let error = transfer(
        &mut host,
        &mut tcp,
        &flow,
        &shared,
        limits,
        deadline,
        &mut frame_boundary,
    )
    .err();
    // Publish terminal state only after the application's TCP descriptor is gone.
    let _ = tcp.shutdown(Shutdown::Both);
    drop(tcp);
    flow.finish(error);
    // A cancelled, partially delivered DATA frame cannot be followed by another
    // header: the peer would interpret FINISHED as that DATA's remaining bytes.
    // Close this transport; the independent info RPC retains the terminal proof.
    if frame_boundary && let Ok(bytes) = serde_json::to_vec(&flow.info()) {
        let _ = write_all(
            &mut host,
            &shared,
            &wire::frame(wire::FINISHED, &bytes),
            Instant::now() + HANDSHAKE_TIMEOUT,
        );
    }
}

enum Message {
    Data(Vec<u8>),
    Eof,
    Cancel,
}
struct Decoder {
    header: [u8; 5],
    head: usize,
    body: Vec<u8>,
    received: usize,
    progressed: bool,
}
impl Decoder {
    fn new() -> Self {
        Self {
            header: [0; 5],
            head: 0,
            body: Vec::new(),
            received: 0,
            progressed: false,
        }
    }
    fn next(&mut self, file: &mut File, allow_data: bool) -> Result<Option<Message>, &'static str> {
        self.progressed = false;
        if self.head < 5 {
            match file.read(&mut self.header[self.head..]) {
                Ok(0) => return Err("connection_lost"),
                Ok(count) => {
                    self.head += count;
                    self.progressed = true;
                }
                Err(e) if retry(&e) => return Ok(None),
                Err(_) => return Err("connection_lost"),
            }
            if self.head < 5 {
                return Ok(None);
            }
        }
        let size = u32::from_be_bytes(self.header[1..].try_into().unwrap()) as usize;
        let kind = self.header[0];
        match kind {
            wire::DATA if allow_data && (1..=wire::MAX_DATA).contains(&size) => (),
            wire::EOF | wire::CANCEL if size == 0 => {
                self.head = 0;
                return Ok(Some(if kind == wire::EOF {
                    Message::Eof
                } else {
                    Message::Cancel
                }));
            }
            _ => return Err("protocol_error"),
        }
        self.body.resize(size, 0);
        match file.read(&mut self.body[self.received..]) {
            Ok(0) => return Err("connection_lost"),
            Ok(count) => {
                self.received += count;
                self.progressed = true;
            }
            Err(e) if retry(&e) => return Ok(None),
            Err(_) => return Err("connection_lost"),
        }
        if self.received != size {
            return Ok(None);
        }
        self.head = 0;
        self.received = 0;
        Ok(Some(Message::Data(std::mem::take(&mut self.body))))
    }
}
struct Pending {
    bytes: Vec<u8>,
    offset: usize,
}
impl Pending {
    fn new() -> Self {
        Self {
            bytes: Vec::new(),
            offset: 0,
        }
    }
    fn empty(&self) -> bool {
        self.offset == self.bytes.len()
    }
    fn put(&mut self, bytes: Vec<u8>) {
        self.bytes = bytes;
        self.offset = 0;
    }
    fn flush(&mut self, stream: &mut impl Write) -> Result<usize, &'static str> {
        if self.empty() {
            return Ok(0);
        }
        match stream.write(&self.bytes[self.offset..]) {
            Ok(0) => Err("io_error"),
            Ok(count) => {
                self.offset += count;
                Ok(count)
            }
            Err(e) if retry(&e) => Ok(0),
            Err(_) => Err("io_error"),
        }
    }
}

fn transfer(
    host: &mut File,
    tcp: &mut TcpStream,
    flow: &Flow,
    control: &Control,
    limits: Limits,
    deadline: Instant,
    frame_boundary: &mut bool,
) -> Result<(), &'static str> {
    let mut decoder = Decoder::new();
    let (mut to_tcp, mut to_host) = (Pending::new(), Pending::new());
    let (mut host_eof, mut tcp_eof, mut write_closed, mut eof_sent) = (false, false, false, false);
    let mut activity = Instant::now();
    loop {
        let now = Instant::now();
        if control.stop.load(Ordering::Acquire) {
            return Err("service_closed");
        }
        if flow.cancel.load(Ordering::Acquire) {
            return Err("cancelled");
        }
        if now >= deadline.min(control.deadline()) {
            return Err("timeout");
        }
        if now.duration_since(activity) >= Duration::from_millis(limits.idle_timeout_ms) {
            return Err("idle_timeout");
        }

        let count = to_tcp.flush(tcp)?;
        if count != 0 {
            flow.sent.fetch_add(count as u64, Ordering::AcqRel);
            activity = Instant::now();
        }
        let previous = to_host.offset;
        let count = to_host.flush(host)?;
        *frame_boundary = to_host.offset == 0 || to_host.empty();
        if count != 0 {
            let delivered = to_host.offset.saturating_sub(5) - previous.saturating_sub(5);
            flow.received.fetch_add(delivered as u64, Ordering::AcqRel);
            activity = Instant::now();
        }
        if host_eof && to_tcp.empty() && !write_closed {
            tcp.shutdown(Shutdown::Write).map_err(|_| "io_error")?;
            write_closed = true;
        }
        if tcp_eof && to_host.empty() && !eof_sent {
            to_host.put(wire::frame(wire::EOF, &[]));
            eof_sent = true;
        }
        if host_eof && tcp_eof && to_tcp.empty() && to_host.empty() {
            return Ok(());
        }

        if to_tcp.empty() {
            match decoder.next(host, !host_eof)? {
                Some(Message::Data(bytes)) => {
                    if bytes.len() as u64 > limits.max_bytes - flow.sent.load(Ordering::Acquire) {
                        return Err("byte_limit");
                    }
                    to_tcp.put(bytes);
                    activity = Instant::now();
                }
                Some(Message::Eof) if !host_eof => {
                    host_eof = true;
                    activity = Instant::now();
                }
                Some(Message::Eof) => return Err("protocol_error"),
                Some(Message::Cancel) => return Err("cancelled"),
                None => (),
            }
            if decoder.progressed {
                activity = Instant::now();
            }
        }
        if !tcp_eof && to_host.empty() {
            let remaining = limits.max_bytes - flow.received.load(Ordering::Acquire);
            let mut bytes = [0; wire::MAX_DATA];
            let capacity = remaining.clamp(1, wire::MAX_DATA as u64) as usize;
            match tcp.read(&mut bytes[..capacity]) {
                Ok(0) => {
                    tcp_eof = true;
                    activity = Instant::now();
                }
                Ok(count) => {
                    if count as u64 > remaining {
                        return Err("byte_limit");
                    }
                    to_host.put(wire::frame(wire::DATA, &bytes[..count]));
                    activity = Instant::now();
                }
                Err(e) if retry(&e) => (),
                Err(_) => return Err("io_error"),
            }
        }
        let host_events = libc::POLLRDHUP
            | if to_tcp.empty() { libc::POLLIN } else { 0 }
            | if !to_host.empty() { libc::POLLOUT } else { 0 };
        let tcp_events = if !tcp_eof && to_host.empty() {
            libc::POLLIN
        } else {
            0
        } | if !to_tcp.empty() { libc::POLLOUT } else { 0 };
        let mut polls = [
            libc::pollfd {
                fd: host.as_raw_fd(),
                events: host_events,
                revents: 0,
            },
            libc::pollfd {
                fd: if tcp_events == 0 { -1 } else { tcp.as_raw_fd() },
                events: tcp_events,
                revents: 0,
            },
        ];
        let until = deadline
            .min(control.deadline())
            .min(activity + Duration::from_millis(limits.idle_timeout_ms));
        let wait = until
            .saturating_duration_since(Instant::now())
            .min(SLICE)
            .as_millis()
            .max(1) as i32;
        if unsafe { libc::poll(polls.as_mut_ptr(), 2, wait) } < 0
            && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
        {
            return Err("io_error");
        }
        // Transport close is cancellation, including when app backpressure has
        // disabled reads. Application half-close uses an explicit EOF frame.
        if polls[0].revents & (libc::POLLHUP | libc::POLLRDHUP | libc::POLLERR | libc::POLLNVAL)
            != 0
        {
            return Err("connection_lost");
        }
    }
}
