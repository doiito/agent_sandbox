use super::*;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;
use std::sync::mpsc;

static NEXT: AtomicUsize = AtomicUsize::new(0);
fn accept(fd: RawFd, deadline: Instant) -> io::Result<Option<File>> {
    let mut p = libc::pollfd {
        fd,
        events: libc::POLLIN,
        revents: 0,
    };
    let wait = deadline
        .saturating_duration_since(Instant::now())
        .as_millis()
        .max(1) as i32;
    if unsafe { libc::poll(&mut p, 1, wait) } <= 0 {
        return Ok(None);
    }
    let fd = unsafe {
        libc::accept4(
            fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Some(unsafe { File::from_raw_fd(fd) }))
}
struct Fixture {
    service: Service,
    path: PathBuf,
}
impl Fixture {
    fn new() -> Self {
        Self::with_acceptor(accept)
    }
    fn with_acceptor(acceptor: Acceptor) -> Self {
        let path = std::env::temp_dir().join(format!(
            "osv-port-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::SeqCst)
        ));
        let listener = UnixListener::bind(&path).unwrap();
        listener.set_nonblocking(true).unwrap();
        let options = Options {
            hard_deadline: Instant::now() + Duration::from_secs(10),
            max_connections: 2,
            max_records: 16,
        };
        let service = Service::start(
            unsafe { File::from_raw_fd(listener.into_raw_fd()) },
            acceptor,
            options,
        )
        .unwrap();
        Self { service, path }
    }
    fn legacy() -> Self {
        let f = Self::new();
        f.service
            .authorize_legacy(Instant::now() + Duration::from_secs(9))
            .unwrap();
        f
    }
    fn socket(&self) -> UnixStream {
        let s = UnixStream::connect(&self.path).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        s.set_write_timeout(Some(Duration::from_secs(3))).unwrap();
        s
    }
    fn rpc(&self, r: &Request) -> wire::Reply {
        let mut s = self.socket();
        send_request(&mut s, r);
        read_reply(&mut s)
    }
    fn open(&self, r: &Request) -> UnixStream {
        let mut s = self.socket();
        send_request(&mut s, r);
        let ack = read_reply(&mut s);
        assert!(ack.error.is_none(), "{ack:?}");
        assert_eq!(ack.response.unwrap().status, "open");
        s
    }
    fn info(&self, r: &Request) -> Info {
        let mut r = r.clone();
        r.operation = "info".into();
        r.limits = None;
        self.rpc(&r).response.unwrap()
    }
    fn cancel(&self, r: &Request) -> Info {
        let mut r = r.clone();
        r.operation = "cancel".into();
        r.limits = None;
        self.rpc(&r).response.unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.service.close().unwrap();
        let _ = std::fs::remove_file(&self.path);
    }
}
fn request(id: u64, port: u16) -> Request {
    Request {
        protocol: wire::PROTOCOL.into(),
        session_id: "a".repeat(24),
        nonce: "b".repeat(64),
        binding: None,
        operation: "open".into(),
        id: format!("{id:024x}"),
        port,
        limits: Some(Limits {
            max_bytes: wire::MAX_BYTES,
            timeout_ms: 5000,
            idle_timeout_ms: 3000,
        }),
    }
}
fn send_request(s: &mut UnixStream, r: &Request) {
    let bytes = serde_json::to_vec(r).unwrap();
    s.write_all(&(bytes.len() as u32).to_be_bytes()).unwrap();
    s.write_all(&bytes).unwrap();
}
fn read_reply(s: &mut UnixStream) -> wire::Reply {
    let mut size = [0; 4];
    s.read_exact(&mut size).unwrap();
    let size = u32::from_be_bytes(size) as usize;
    assert!(size <= wire::MAX_HANDSHAKE);
    let mut bytes = vec![0; size];
    s.read_exact(&mut bytes).unwrap();
    serde_json::from_slice(&bytes).unwrap()
}
fn read_frame(s: &mut UnixStream) -> (u8, Vec<u8>) {
    let mut header = [0; 5];
    s.read_exact(&mut header).unwrap();
    let n = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
    assert!(n <= wire::MAX_DATA);
    let mut body = vec![0; n];
    s.read_exact(&mut body).unwrap();
    (header[0], body)
}
fn finish(s: &mut UnixStream) -> (Vec<u8>, Info) {
    let mut output = Vec::new();
    let mut eof = false;
    loop {
        let (kind, data) = read_frame(s);
        match kind {
            wire::DATA => {
                assert!(!eof);
                output.extend(data);
            }
            wire::EOF => {
                assert!(data.is_empty() && !eof);
                eof = true;
            }
            wire::FINISHED => return (output, serde_json::from_slice(&data).unwrap()),
            _ => panic!("unexpected frame"),
        }
    }
}
fn application(action: impl FnOnce(TcpStream) + Send + 'static) -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let worker = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(4)))
            .unwrap();
        action(stream);
    });
    (port, worker)
}
fn wait(mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !check() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn strict_wire_rejects_unbound_addresses_bad_ids_and_limits() {
    let r = request(1, 8080);
    let mut value = serde_json::to_value(&r).unwrap();
    assert!(Request::parse(&serde_json::to_vec(&value).unwrap()).is_ok());
    for (key, v) in [
        ("port", serde_json::json!(0)),
        ("port", serde_json::json!(-1)),
        ("port", serde_json::json!(65536)),
        ("port", serde_json::json!(true)),
        ("address", serde_json::json!("169.254.169.254")),
        ("id", serde_json::json!("A".repeat(24))),
    ] {
        let mut bad = value.clone();
        bad[key] = v;
        assert!(Request::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    value["limits"]["max_bytes"] = serde_json::json!(wire::MAX_BYTES + 1);
    assert!(Request::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    assert!(Request::parse(&vec![b' '; wire::MAX_HANDSHAKE + 1]).is_err());
}
#[test]
fn pending_authorization_never_dials_application() {
    let f = Fixture::new();
    let app = TcpListener::bind("127.0.0.1:0").unwrap();
    app.set_nonblocking(true).unwrap();
    assert_eq!(
        f.rpc(&request(1, app.local_addr().unwrap().port()))
            .error
            .as_deref(),
        Some("unsupported")
    );
    assert!(app.accept().is_err());
    assert_eq!(f.service.active_connections(), 0);
}

#[test]
fn readiness_reports_real_policy_and_never_revives_after_revoke() {
    let f = Fixture::new();
    let r = f.service.readiness().unwrap();
    assert_eq!(r.state, "pending");
    assert_eq!(r.protocol, wire::PROTOCOL);
    assert_eq!(r.port, 5004);
    assert_eq!(r.target, "ipv4_loopback");
    assert_eq!((r.max_connections, r.max_records), (2, 16));
    assert_eq!(r.max_frame_bytes, wire::MAX_DATA);
    assert_eq!(r.max_bytes, wire::MAX_BYTES);
    assert_eq!(r.max_duration_ms, wire::MAX_DURATION_MS);
    f.service
        .authorize_legacy(Instant::now() + Duration::from_secs(8))
        .unwrap();
    assert_eq!(f.service.readiness().unwrap().state, "session");
    f.service.revoke();
    assert!(f.service.readiness().is_none());
    assert!(
        f.service
            .authorize_legacy(Instant::now() + Duration::from_secs(8))
            .is_err()
    );
    assert!(f.service.readiness().is_none());
}
#[test]
fn prepared_binding_is_checked_before_dial_and_cannot_be_replaced() {
    let f = Fixture::new();
    let binding = Binding {
        session_id: "a".repeat(24),
        nonce: "c".repeat(64),
    };
    f.service
        .authorize_prepared(binding.clone(), Instant::now() + Duration::from_secs(8))
        .unwrap();
    let app = TcpListener::bind("127.0.0.1:0").unwrap();
    app.set_nonblocking(true).unwrap();
    let mut r = request(1, app.local_addr().unwrap().port());
    assert_eq!(f.rpc(&r).error.as_deref(), Some("invalid_binding"));
    r.binding = Some(Binding {
        nonce: "d".repeat(64),
        ..binding.clone()
    });
    assert_eq!(f.rpc(&r).error.as_deref(), Some("invalid_binding"));
    assert!(app.accept().is_err());
    assert!(
        f.service
            .authorize_prepared(
                Binding {
                    nonce: "e".repeat(64),
                    ..binding.clone()
                },
                Instant::now() + Duration::from_secs(8)
            )
            .is_err()
    );
    r.binding = Some(binding);
    assert_eq!(f.cancel(&r).status, "cancelled");
}
#[test]
fn legacy_owner_is_pinned_without_switching_on_wrong_sid() {
    let f = Fixture::legacy();
    let r = request(1, 8080);
    assert_eq!(f.cancel(&r).status, "cancelled");
    let mut foreign = r.clone();
    foreign.session_id = "f".repeat(24);
    foreign.operation = "info".into();
    foreign.limits = None;
    assert_eq!(f.rpc(&foreign).error.as_deref(), Some("invalid_binding"));
    assert_eq!(f.info(&r).status, "cancelled");
}
#[test]
fn cancel_before_open_is_terminal_and_prevents_late_dial() {
    let f = Fixture::legacy();
    let app = TcpListener::bind("127.0.0.1:0").unwrap();
    app.set_nonblocking(true).unwrap();
    let r = request(1, app.local_addr().unwrap().port());
    assert_eq!(f.cancel(&r).status, "cancelled");
    assert_eq!(f.cancel(&r).status, "cancelled");
    assert_eq!(f.rpc(&r).error.as_deref(), Some("cancelled"));
    assert!(app.accept().is_err());
    assert_eq!(f.service.active_connections(), 0);
}
#[test]
fn handshake_pipeline_binary_data_and_host_half_close_are_lossless() {
    let f = Fixture::legacy();
    let payload: Vec<u8> = (0..200000).map(|i| (i % 256) as u8).collect();
    let expected = payload.clone();
    let (port, app) = application(move |mut s| {
        let mut data = Vec::new();
        s.read_to_end(&mut data).unwrap();
        assert_eq!(data, expected);
        s.write_all(b"reply\0\xff").unwrap();
    });
    let r = request(1, port);
    let mut s = f.socket();
    let bytes = serde_json::to_vec(&r).unwrap();
    let mut packet = (bytes.len() as u32).to_be_bytes().to_vec();
    packet.extend(bytes);
    packet.extend(wire::frame(wire::DATA, &payload[..123]));
    s.write_all(&packet).unwrap();
    let ack = read_reply(&mut s);
    assert_eq!(ack.nonce, r.nonce);
    assert!(ack.error.is_none());
    for chunk in payload[123..].chunks(wire::MAX_DATA) {
        s.write_all(&wire::frame(wire::DATA, chunk)).unwrap();
    }
    s.write_all(&wire::frame(wire::EOF, &[])).unwrap();
    let (output, info) = finish(&mut s);
    assert_eq!(output, b"reply\0\xff");
    assert_eq!(info.status, "completed");
    assert_eq!(info.sent_bytes, payload.len() as u64);
    assert_eq!(info.received_bytes, b"reply\0\xff".len() as u64);
    app.join().unwrap();
    assert_eq!(f.rpc(&r).error.as_deref(), Some("conflict"));
}
#[test]
fn application_half_close_still_accepts_reverse_data() {
    let f = Fixture::legacy();
    let (port, app) = application(|mut s| {
        s.write_all(b"first").unwrap();
        s.shutdown(Shutdown::Write).unwrap();
        let mut input = Vec::new();
        s.read_to_end(&mut input).unwrap();
        assert_eq!(input, b"after eof");
    });
    let r = request(1, port);
    let mut s = f.open(&r);
    let mut bytes = Vec::new();
    loop {
        let (kind, data) = read_frame(&mut s);
        if kind == wire::EOF {
            break;
        }
        assert_eq!(kind, wire::DATA);
        bytes.extend(data);
    }
    assert_eq!(bytes, b"first");
    s.write_all(&wire::frame(wire::DATA, b"after eof")).unwrap();
    s.write_all(&wire::frame(wire::EOF, &[])).unwrap();
    let (_, info) = finish(&mut s);
    assert_eq!(info.status, "completed");
    assert_eq!(info.sent_bytes, 9);
    assert_eq!(info.received_bytes, 5);
    app.join().unwrap();
}
#[test]
fn fragmented_data_activity_resets_idle_timer_without_resetting_total_limit() {
    let f = Fixture::legacy();
    let (port, app) = application(|mut s| {
        let mut data = Vec::new();
        s.read_to_end(&mut data).unwrap();
        assert_eq!(data, vec![42; 200]);
    });
    let mut r = request(1, port);
    r.limits.as_mut().unwrap().idle_timeout_ms = 200;
    let mut s = f.open(&r);
    let frame = wire::frame(wire::DATA, &[42; 200]);
    for part in frame.chunks(20) {
        s.write_all(part).unwrap();
        thread::sleep(Duration::from_millis(30));
    }
    s.write_all(&wire::frame(wire::EOF, &[])).unwrap();
    assert_eq!(finish(&mut s).1.status, "completed");
    app.join().unwrap();
}
#[test]
fn cancel_and_info_remain_available_at_data_capacity_and_slots_recover() {
    let f = Fixture::legacy();
    let (release, blocked) = mpsc::channel();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let app = thread::spawn(move || {
        let mut peers = Vec::new();
        for _ in 0..3 {
            peers.push(listener.accept().unwrap().0);
        }
        blocked.recv_timeout(Duration::from_secs(4)).unwrap();
        drop(peers);
    });
    let r1 = request(1, port);
    let mut s1 = f.open(&r1);
    let r2 = request(2, port);
    let mut s2 = f.open(&r2);
    assert_eq!(f.rpc(&request(3, port)).error.as_deref(), Some("quota"));
    assert_eq!(f.info(&r2).status, "open");
    assert!(matches!(
        f.cancel(&r1).status.as_str(),
        "cancelling" | "cancelled"
    ));
    assert_eq!(finish(&mut s1).1.status, "cancelled");
    wait(|| f.service.active_connections() < 2);
    let r4 = request(4, port);
    let mut s4 = f.open(&r4);
    f.cancel(&r2);
    f.cancel(&r4);
    assert_eq!(finish(&mut s2).1.status, "cancelled");
    assert_eq!(finish(&mut s4).1.status, "cancelled");
    release.send(()).unwrap();
    app.join().unwrap();
    wait(|| f.service.active_connections() == 0);
}
#[test]
fn record_budget_keeps_existing_cancel_and_info_working() {
    let f = Fixture::legacy();
    for id in 1..=16 {
        assert_eq!(f.cancel(&request(id, 8080)).status, "cancelled");
    }
    assert_eq!(f.rpc(&request(17, 8080)).error.as_deref(), Some("quota"));
    assert_eq!(f.cancel(&request(1, 8080)).status, "cancelled");
    assert_eq!(f.info(&request(1, 8080)).status, "cancelled");
    let mut wrong = request(1, 8081);
    wrong.operation = "cancel".into();
    wrong.limits = None;
    assert_eq!(f.rpc(&wrong).error.as_deref(), Some("invalid_binding"));
}
#[test]
fn exact_output_budget_can_finish_but_extra_byte_is_reported() {
    for overflow in [false, true] {
        let f = Fixture::legacy();
        let (port, app) = application(move |mut s| {
            // Overflow may legitimately terminate before a late host EOF.
            // Establish the input half-close before exercising output quota.
            assert_eq!(s.read(&mut [0; 1]).unwrap(), 0);
            let _ = s.write_all(if overflow { b"abcdx" } else { b"abcd" });
            s.shutdown(Shutdown::Write).unwrap();
        });
        let mut r = request(1, port);
        r.limits.as_mut().unwrap().max_bytes = 4;
        let mut s = f.open(&r);
        s.write_all(&wire::frame(wire::EOF, &[])).unwrap();
        let (data, info) = finish(&mut s);
        assert_eq!(data, b"abcd");
        assert_eq!(info.received_bytes, 4);
        assert_eq!(
            info.error.as_deref(),
            if overflow { Some("byte_limit") } else { None }
        );
        app.join().unwrap();
    }
}
#[test]
fn invalid_data_after_half_close_and_oversized_frames_are_terminal_errors() {
    for malformed in [
        wire::frame(wire::DATA, &[]),
        vec![wire::DATA, 0, 1, 0, 0],
        wire::frame(wire::FINISHED, b"{}"),
    ] {
        let f = Fixture::legacy();
        let (port, app) = application(|mut s| {
            let mut input = Vec::new();
            let _ = s.read_to_end(&mut input);
            assert!(input.is_empty());
        });
        let r = request(1, port);
        let mut s = f.open(&r);
        s.write_all(&malformed).unwrap();
        assert_eq!(finish(&mut s).1.error.as_deref(), Some("protocol_error"));
        app.join().unwrap();
    }
    let f = Fixture::legacy();
    let (port, app) = application(|mut s| {
        let mut b = Vec::new();
        s.read_to_end(&mut b).unwrap();
        thread::sleep(Duration::from_millis(50));
    });
    let r = request(1, port);
    let mut s = f.open(&r);
    let mut packet = wire::frame(wire::EOF, &[]);
    packet.extend(wire::frame(wire::DATA, b"bad"));
    s.write_all(&packet).unwrap();
    assert_eq!(finish(&mut s).1.error.as_deref(), Some("protocol_error"));
    app.join().unwrap();
}
#[test]
fn idle_and_absolute_timeout_close_application_before_terminal_info() {
    for idle in [true, false] {
        let f = Fixture::legacy();
        let (port, app) = application(|mut s| {
            assert_eq!(s.read(&mut [0; 1]).unwrap(), 0);
        });
        let mut r = request(1, port);
        if idle {
            r.limits.as_mut().unwrap().idle_timeout_ms = 80;
        } else {
            r.limits.as_mut().unwrap().timeout_ms = 80;
        }
        let mut s = f.open(&r);
        let info = finish(&mut s).1;
        assert_eq!(
            info.error.as_deref(),
            Some(if idle { "idle_timeout" } else { "timeout" })
        );
        assert_eq!(f.info(&r).status, "failed");
        app.join().unwrap();
    }
}
#[test]
fn revoke_closes_live_and_incomplete_control_sockets_and_is_irreversible() {
    let mut f = Fixture::legacy();
    let (port, app) = application(|mut s| {
        assert_eq!(s.read(&mut [0; 1]).unwrap(), 0);
    });
    let r = request(1, port);
    let mut data = f.open(&r);
    let mut incomplete = f.socket();
    incomplete.write_all(&[0, 0]).unwrap();
    let before = Instant::now();
    f.service.close().unwrap();
    assert!(before.elapsed() < Duration::from_secs(1));
    assert_eq!(f.service.active_connections(), 0);
    assert!(matches!(data.read(&mut [0; 1]), Ok(0) | Err(_)));
    assert!(matches!(incomplete.read(&mut [0; 1]), Ok(0) | Err(_)));
    assert!(
        f.service
            .authorize_legacy(Instant::now() + Duration::from_secs(8))
            .is_err()
    );
    app.join().unwrap();
}
#[test]
fn refused_connect_has_known_terminal_identity_and_never_replays() {
    let f = Fixture::legacy();
    let port = TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let r = request(1, port);
    let reply = f.rpc(&r);
    assert_eq!(reply.error.as_deref(), Some("connection_refused"));
    assert_eq!(reply.id, r.id);
    assert_eq!(reply.nonce, r.nonce);
    assert_eq!(f.info(&r).error.as_deref(), Some("connection_refused"));
    assert_eq!(f.rpc(&r).error.as_deref(), Some("conflict"));
}

fn blocked_application() -> (u16, mpsc::Sender<()>, mpsc::Receiver<()>, JoinHandle<()>) {
    let (release, blocked) = mpsc::channel();
    let (ready, accepted) = mpsc::channel();
    let (port, app) = application(move |mut s| {
        let size: libc::c_int = 4096;
        assert_eq!(
            unsafe {
                libc::setsockopt(
                    s.as_raw_fd(),
                    libc::SOL_SOCKET,
                    libc::SO_RCVBUF,
                    (&size as *const libc::c_int).cast(),
                    std::mem::size_of_val(&size) as libc::socklen_t,
                )
            },
            0
        );
        ready.send(()).unwrap();
        blocked.recv_timeout(Duration::from_secs(4)).unwrap();
        let mut received = 0;
        let mut bytes = [0; 4096];
        loop {
            match s.read(&mut bytes) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    received += n;
                    assert!(received <= wire::MAX_BYTES as usize);
                }
            }
        }
    });
    (port, release, accepted, app)
}
#[test]
fn independent_cancel_interrupts_real_application_backpressure() {
    let f = Fixture::legacy();
    let (port, release, accepted, app) = blocked_application();
    let r = request(1, port);
    let mut s = f.open(&r);
    accepted.recv_timeout(Duration::from_secs(1)).unwrap();
    let mut sender = s.try_clone().unwrap();
    let writer = thread::spawn(move || {
        let frame = wire::frame(wire::DATA, &vec![7; wire::MAX_DATA]);
        for _ in 0..512 {
            if sender.write_all(&frame).is_err() {
                return;
            }
        }
        panic!("backpressure was not exercised");
    });
    wait(|| f.info(&r).sent_bytes >= 64 * 1024);
    assert!(!writer.is_finished());
    f.cancel(&r);
    let info = finish(&mut s).1;
    assert_eq!(info.status, "cancelled");
    assert_eq!(f.info(&r).status, "cancelled");
    writer.join().unwrap();
    wait(|| f.service.active_connections() == 0);
    release.send(()).unwrap();
    app.join().unwrap();
}
#[test]
fn raw_transport_hangup_interrupts_backpressure_without_waiting_for_idle() {
    let f = Fixture::legacy();
    let (port, release, accepted, app) = blocked_application();
    let r = request(1, port);
    let s = f.open(&r);
    accepted.recv_timeout(Duration::from_secs(1)).unwrap();
    let mut sender = s.try_clone().unwrap();
    let writer = thread::spawn(move || {
        let frame = wire::frame(wire::DATA, &vec![7; wire::MAX_DATA]);
        for _ in 0..512 {
            if sender.write_all(&frame).is_err() {
                return;
            }
        }
        panic!("backpressure was not exercised");
    });
    wait(|| f.info(&r).sent_bytes >= 64 * 1024);
    assert!(!writer.is_finished());
    let before = Instant::now();
    s.shutdown(Shutdown::Both).unwrap();
    drop(s);
    wait(|| f.info(&r).status == "failed");
    assert_eq!(f.info(&r).error.as_deref(), Some("connection_lost"));
    wait(|| f.service.active_connections() == 0);
    assert!(before.elapsed() < Duration::from_secs(1));
    writer.join().unwrap();
    release.send(()).unwrap();
    app.join().unwrap();
}
#[test]
fn input_budget_counts_only_bytes_written_before_rejected_frame() {
    let f = Fixture::legacy();
    let (port, app) = application(|mut s| {
        let mut data = Vec::new();
        s.read_to_end(&mut data).unwrap();
        assert_eq!(data, b"abcd");
    });
    let mut r = request(1, port);
    r.limits.as_mut().unwrap().max_bytes = 4;
    let mut s = f.open(&r);
    let mut data = wire::frame(wire::DATA, b"abcd");
    data.extend(wire::frame(wire::DATA, b"x"));
    s.write_all(&data).unwrap();
    let info = finish(&mut s).1;
    assert_eq!(info.error.as_deref(), Some("byte_limit"));
    assert_eq!(info.sent_bytes, 4);
    app.join().unwrap();
}

fn accept_small_send_buffer(fd: RawFd, deadline: Instant) -> io::Result<Option<File>> {
    let accepted = accept(fd, deadline)?;
    if let Some(file) = &accepted {
        let size: libc::c_int = 4096;
        if unsafe {
            libc::setsockopt(
                file.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                (&size as *const libc::c_int).cast(),
                std::mem::size_of_val(&size) as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(accepted)
}

#[test]
fn cancellation_never_splices_terminal_json_into_a_partially_written_data_frame() {
    let f = Fixture::with_acceptor(accept_small_send_buffer);
    f.service
        .authorize_legacy(Instant::now() + Duration::from_secs(9))
        .unwrap();
    let (port, app) = application(|mut s| {
        let _ = s.write_all(&vec![0xa5; 1024 * 1024]);
    });
    let r = request(1, port);
    let mut s = f.open(&r);
    // Do not read DATA. The small real transport buffer forces a partial write.
    wait(|| f.info(&r).received_bytes > 0);
    thread::sleep(Duration::from_millis(100));
    let before = Instant::now();
    f.cancel(&r);
    wait(|| f.info(&r).status == "cancelled");
    wait(|| f.service.active_connections() == 0);
    assert!(before.elapsed() < Duration::from_secs(1));
    let info = f.info(&r);
    let mut bytes = Vec::new();
    s.read_to_end(&mut bytes).unwrap();
    let mut offset = 0;
    let mut delivered = 0;
    let mut partial = false;
    while offset < bytes.len() {
        assert!(
            bytes.len() - offset >= 5,
            "partial header was not the exercised boundary"
        );
        assert_eq!(bytes[offset], wire::DATA);
        let size = u32::from_be_bytes(bytes[offset + 1..offset + 5].try_into().unwrap()) as usize;
        assert!((1..=wire::MAX_DATA).contains(&size));
        offset += 5;
        let available = size.min(bytes.len() - offset);
        assert!(
            bytes[offset..offset + available].iter().all(|&b| b == 0xa5),
            "terminal JSON was spliced into application payload"
        );
        delivered += available;
        offset += available;
        if available < size {
            partial = true;
            break;
        }
    }
    assert!(partial, "test did not force a partially written DATA frame");
    assert_eq!(info.received_bytes, delivered as u64);
    app.join().unwrap();
}
