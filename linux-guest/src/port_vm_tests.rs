//! Actual PID1 main-handler authorization plus production relay/loopback TCP.
use super::*;
use port_service::wire;
use std::net::{TcpListener, TcpStream};
use std::os::fd::IntoRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::{AtomicU64, Ordering};

static NEXT: AtomicU64 = AtomicU64::new(1);
fn id() -> String {
    format!("{:024x}", NEXT.fetch_add(1, Ordering::Relaxed))
}
fn accept(listener: RawFd, deadline: Instant) -> io::Result<Option<File>> {
    let mut fd = libc::pollfd {
        fd: listener,
        events: libc::POLLIN,
        revents: 0,
    };
    if unsafe {
        libc::poll(
            &mut fd,
            1,
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis()
                .max(1) as i32,
        )
    } <= 0
    {
        return Ok(None);
    }
    let raw = unsafe {
        libc::accept4(
            listener,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Some(unsafe { File::from_raw_fd(raw) }))
}
struct Ports {
    service: port_service::Service,
    path: String,
}
impl Ports {
    fn start(hard: Instant) -> Self {
        let path = format!("/run/ports-{}.sock", id());
        let listener = UnixListener::bind(&path).unwrap();
        let service = port_service::Service::start(
            unsafe { File::from_raw_fd(listener.into_raw_fd()) },
            accept,
            port_service::Options::packaged(hard),
        )
        .unwrap();
        Self { service, path }
    }
}
impl Drop for Ports {
    fn drop(&mut self) {
        self.service.close().unwrap();
        fs::remove_file(&self.path).unwrap();
    }
}
fn request(port: u16, binding: Option<&pristine::Binding>) -> port_service::Request {
    port_service::Request {
        protocol: wire::PROTOCOL.into(),
        session_id: "a".repeat(24),
        nonce: format!("{:064x}", NEXT.fetch_add(1, Ordering::Relaxed)),
        binding: binding.map(|b| port_service::Binding {
            session_id: b.session_id.clone(),
            nonce: b.nonce.clone(),
        }),
        operation: "open".into(),
        id: id(),
        port,
        limits: Some(port_service::Limits {
            max_bytes: wire::MAX_BYTES,
            timeout_ms: 10000,
            idle_timeout_ms: 10000,
        }),
    }
}
fn send(path: &str, r: &port_service::Request) -> io::Result<(UnixStream, wire::Reply)> {
    let mut s = UnixStream::connect(path)?;
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    s.set_write_timeout(Some(Duration::from_secs(5)))?;
    let bytes = serde_json::to_vec(r)?;
    s.write_all(&(bytes.len() as u32).to_be_bytes())?;
    s.write_all(&bytes)?;
    let mut header = [0; 4];
    s.read_exact(&mut header)?;
    let size = u32::from_be_bytes(header) as usize;
    assert!(size <= wire::MAX_HANDSHAKE);
    let mut bytes = vec![0; size];
    s.read_exact(&mut bytes)?;
    let reply: wire::Reply = serde_json::from_slice(&bytes)?;
    assert_eq!(reply.nonce, r.nonce);
    assert_eq!(reply.id, r.id);
    assert_eq!(reply.port, r.port);
    assert_eq!(reply.binding, r.binding);
    Ok((s, reply))
}
fn frame(s: &mut UnixStream) -> (u8, Vec<u8>) {
    let mut head = [0; 5];
    s.read_exact(&mut head).unwrap();
    let n = u32::from_be_bytes(head[1..].try_into().unwrap()) as usize;
    assert!(n <= wire::MAX_DATA);
    let mut body = vec![0; n];
    s.read_exact(&mut body).unwrap();
    (head[0], body)
}
fn roundtrip(path: &str, r: &port_service::Request, data: &[u8]) {
    let (mut s, reply) = send(path, r).unwrap();
    assert!(reply.error.is_none(), "{reply:?}");
    assert_eq!(reply.response.unwrap().status, "open");
    s.write_all(&wire::frame(wire::DATA, data)).unwrap();
    s.write_all(&wire::frame(wire::EOF, &[])).unwrap();
    let mut out = Vec::new();
    let mut eof = false;
    loop {
        let (kind, body) = frame(&mut s);
        match kind {
            wire::DATA => {
                assert!(!eof);
                out.extend(body);
            }
            wire::EOF => {
                assert!(body.is_empty());
                eof = true;
            }
            wire::FINISHED => {
                let info: port_service::Info = serde_json::from_slice(&body).unwrap();
                assert_eq!(info.status, "completed");
                assert_eq!(info.sent_bytes, data.len() as u64);
                assert_eq!(info.received_bytes, data.len() as u64);
                break;
            }
            _ => panic!("bad relay frame"),
        }
    }
    assert_eq!(out, data);
}
fn app(action: impl FnOnce(TcpStream) + Send + 'static) -> (u16, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let worker = thread::spawn(move || {
        let (s, _) = listener.accept().unwrap();
        s.set_read_timeout(Some(Duration::from_secs(10))).unwrap();
        s.set_write_timeout(Some(Duration::from_secs(10))).unwrap();
        action(s);
    });
    (port, worker)
}
fn echo() -> (u16, thread::JoinHandle<()>) {
    app(|mut s| {
        let mut data = Vec::new();
        s.read_to_end(&mut data).unwrap();
        s.write_all(&data).unwrap();
    })
}
fn ping(protocol: &str) -> serde_json::Value {
    serde_json::json!({"protocol":protocol,"job_id":id(),"operation":"ping"})
}
fn main_rpc(
    ports: &Ports,
    runtime: &mut pristine::Runtime,
    request: serde_json::Value,
) -> (ConnectionAction, serde_json::Value) {
    let (mut client, server) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    writeln!(client, "{request}").unwrap();
    let action = handle_connection_all(
        unsafe { File::from_raw_fd(server.into_raw_fd()) },
        None,
        Instant::now() + Duration::from_secs(120),
        runtime,
        None,
        None,
        Some(&ports.service),
    );
    let mut line = String::new();
    BufReader::new(client).read_line(&mut line).unwrap();
    let reply = serde_json::from_str(line.strip_prefix(RESULT_PREFIX).unwrap()).unwrap();
    (action, reply)
}
fn wait(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(6);
    while !condition() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
}
fn reset_input() {
    fs::create_dir_all("/input").unwrap();
    let path = CString::new("/input").unwrap();
    unsafe {
        libc::umount(path.as_ptr());
    }
    mount_required("tmpfs", "/input", "tmpfs", 0, Some("size=1m,mode=0755")).unwrap();
}
fn prepare(binding: &pristine::Binding, mode: &str) -> serde_json::Value {
    serde_json::json!({"protocol":pristine::PROTOCOL,"job_id":id(),"operation":"prepare","prepare":{"binding":binding,"mode":mode,"ttl_ms":10000,"network":"none","input_files":[]}})
}

fn assert_readiness(reply: &serde_json::Value, state: &str) {
    assert_eq!(
        reply["port_service"],
        serde_json::json!({
            "revision":1,"protocol":"fc-port/v1","port":5004,"target":"ipv4_loopback","state":state,
            "max_connections":8,"max_records":256,"max_frame_bytes":16384,"max_bytes":67108864,"max_duration_ms":300000
        })
    );
}

#[test]
fn port_boot_policy_requires_one_explicit_flag_and_successful_init() {
    assert!(!port_policy("").unwrap());
    assert!(port_policy("quiet agent.port=5004").unwrap());
    for line in [
        "agent.port=5003",
        "agent.port=5004 agent.port=5004",
        "agent.port=0",
        "agent.port=5004x",
    ] {
        assert!(port_policy(line).is_err());
    }
    assert!(
        start_port_service(
            "",
            Some("failed root"),
            Instant::now() + Duration::from_secs(10)
        )
        .unwrap()
        .is_none()
    );
    assert!(
        start_port_service(
            "agent.port=5004",
            Some("failed root"),
            Instant::now() + Duration::from_secs(10)
        )
        .is_err()
    );
}

#[test]
#[ignore = "requires isolated guest PID1, loopback and real cgroup supervision"]
fn actual_session_port_service_at_pid_one() {
    workload_vm_tests::setup_guest();
    network_proxy::enable_loopback().unwrap();
    let mut command = Command::new("/bin/bash");
    command.env_clear();
    network_proxy::configure_command(&mut command);
    assert!(command.get_envs().next().is_none());
    assert!(TcpStream::connect("127.0.0.1:3128").is_err());
    assert!(
        fs::read_to_string("/proc/net/dev")
            .unwrap()
            .lines()
            .skip(2)
            .all(|line| line.trim_start().starts_with("lo:"))
    );
    println!("PASS port-service-loopback-without-nic-or-egress-proxy");
    let ports = Ports::start(Instant::now() + Duration::from_secs(120));
    let mut runtime = pristine::Runtime::Legacy;
    let unopened = TcpListener::bind("127.0.0.1:0").unwrap();
    unopened.set_nonblocking(true).unwrap();
    let r = request(unopened.local_addr().unwrap().port(), None);
    assert_eq!(
        send(&ports.path, &r).unwrap().1.error.as_deref(),
        Some("unsupported")
    );
    assert!(unopened.accept().is_err());
    let (_, reply) = main_rpc(
        &ports,
        &mut runtime,
        serde_json::json!({"protocol":SESSION_PROTOCOL,"job_id":id(),"operation":"invalid"}),
    );
    assert_eq!(reply["ok"], false);
    assert_eq!(
        send(&ports.path, &r).unwrap().1.error.as_deref(),
        Some("unsupported")
    );
    let (_, reply) = main_rpc(&ports, &mut runtime, ping(SESSION_PROTOCOL));
    assert_eq!(reply["ok"], true);
    assert_readiness(&reply, "session");
    let (port, worker) = echo();
    roundtrip(&ports.path, &request(port, None), b"pid1\0binary\xff");
    worker.join().unwrap();
    println!("PASS port-service-legacy-ping-ack-authorizes-binary-half-close");
    let (port, worker) = echo();
    let path = ports.path.clone();
    let r = request(port, None);
    let client = thread::spawn(move || {
        thread::sleep(Duration::from_millis(20));
        roundtrip(&path, &r, b"during foreground");
    });
    let (_, reply) = main_rpc(
        &ports,
        &mut runtime,
        serde_json::json!({"protocol":SESSION_PROTOCOL,"job_id":id(),"operation":"run","argv":["/bin/bash","-c","sleep .2; printf foreground"],"timeout_ms":5000,"max_output_bytes":4096}),
    );
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(reply["stdout"], "foreground");
    client.join().unwrap();
    worker.join().unwrap();
    println!("PASS port-service-independent-during-real-shell-command");
    let (port, worker) = app(|mut s| {
        assert_eq!(s.read(&mut [0; 1]).unwrap(), 0);
    });
    let (_live, ack) = send(&ports.path, &request(port, None)).unwrap();
    assert!(ack.error.is_none());
    let (action, reply) = main_rpc(
        &ports,
        &mut runtime,
        serde_json::json!({"protocol":SESSION_PROTOCOL,"job_id":id(),"operation":"shutdown"}),
    );
    assert_eq!(action, ConnectionAction::Poweroff);
    assert_eq!(reply["ok"], true);
    assert!(reply.get("port_service").is_none());
    assert!(ports.service.readiness().is_none());
    wait(|| ports.service.active_connections() == 0);
    worker.join().unwrap();
    assert!(
        ports
            .service
            .authorize_legacy(Instant::now() + Duration::from_secs(30))
            .is_err()
    );
    drop(ports);
    println!("PASS port-service-main-shutdown-revokes-and-reaps-tcp");

    reset_input();
    let ports = Ports::start(Instant::now() + Duration::from_secs(120));
    let mut runtime = pristine::Runtime::Pristine;
    let binding = pristine::Binding {
        session_id: "a".repeat(24),
        nonce: "d".repeat(64),
    };
    let r = request(unopened.local_addr().unwrap().port(), Some(&binding));
    let (_, reply) = main_rpc(&ports, &mut runtime, ping(pristine::PROTOCOL));
    assert_eq!(reply["guest_state"], "pristine");
    assert_readiness(&reply, "pending");
    assert_eq!(
        send(&ports.path, &r).unwrap().1.error.as_deref(),
        Some("unsupported")
    );
    let (_, reply) = main_rpc(&ports, &mut runtime, prepare(&binding, "session"));
    assert_eq!(reply["ok"], true, "{reply}");
    assert_eq!(reply["binding"], serde_json::to_value(&binding).unwrap());
    assert_readiness(&reply, "session");
    assert!(fs::write("/input/forbidden", b"x").is_err());
    let mut wrong = r.clone();
    wrong.binding.as_mut().unwrap().nonce = "e".repeat(64);
    assert_eq!(
        send(&ports.path, &wrong).unwrap().1.error.as_deref(),
        Some("invalid_binding")
    );
    assert!(unopened.accept().is_err());
    let (port, worker) = echo();
    roundtrip(
        &ports.path,
        &request(port, Some(&binding)),
        b"prepared data",
    );
    worker.join().unwrap();
    println!("PASS port-service-prepared-ack-binding-readonly-input-and-data");
    let (port, worker) = app(|mut s| {
        assert_eq!(s.read(&mut [0; 1]).unwrap(), 0);
    });
    let (_live, ack) = send(&ports.path, &request(port, Some(&binding))).unwrap();
    assert!(ack.error.is_none());
    let (action, reply) = main_rpc(
        &ports,
        &mut runtime,
        serde_json::json!({"protocol":pristine::PROTOCOL,"job_id":id(),"operation":"ping","binding":{"session_id":binding.session_id,"nonce":"f".repeat(64)}}),
    );
    assert_eq!(action, ConnectionAction::Poweroff);
    assert_eq!(reply["ok"], false);
    assert!(reply.get("port_service").is_none());
    assert!(ports.service.readiness().is_none());
    wait(|| ports.service.active_connections() == 0);
    worker.join().unwrap();
    drop(ports);
    println!("PASS port-service-poisoned-main-binding-revokes-live-tcp");

    reset_input();
    let ports = Ports::start(Instant::now() + Duration::from_secs(120));
    let mut runtime = pristine::Runtime::Pristine;
    let (_, reply) = main_rpc(&ports, &mut runtime, prepare(&binding, "job"));
    assert_eq!(reply["ok"], true, "{reply}");
    assert!(reply.get("port_service").is_none());
    assert!(
        ports
            .service
            .authorize_prepared(
                port_service::Binding {
                    session_id: binding.session_id.clone(),
                    nonce: binding.nonce.clone()
                },
                Instant::now() + Duration::from_secs(30)
            )
            .is_err()
    );
    if let Ok((_, reply)) = send(
        &ports.path,
        &request(unopened.local_addr().unwrap().port(), Some(&binding)),
    ) {
        assert!(reply.error.is_some());
    };
    assert!(unopened.accept().is_err());
    drop(ports);
    println!("PASS port-service-one-shot-prepare-never-authorizes-dial");

    let ports = Ports::start(Instant::now() + Duration::from_secs(2));
    let mut runtime = pristine::Runtime::Legacy;
    assert_eq!(
        main_rpc(&ports, &mut runtime, ping(SESSION_PROTOCOL)).1["ok"],
        true
    );
    let (port, worker) = app(|mut s| {
        assert_eq!(s.read(&mut [0; 1]).unwrap(), 0);
    });
    let (_live, ack) = send(&ports.path, &request(port, None)).unwrap();
    assert!(ack.error.is_none());
    wait(|| ports.service.active_connections() == 0);
    worker.join().unwrap();
    assert!(ports.service.readiness().is_none());
    drop(ports);
    println!("PASS port-service-hard-lease-cleans-up-without-main-traffic");
    assert!(!workload::unusable());
    assert_eq!(
        fs::read_dir("/run/osv-workloads")
            .unwrap()
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().starts_with('w'))
            .count(),
        0
    );
    println!("PASS port-service-zero-workload-cgroups-after-parallel-command");
    println!("RUST_PORT_SERVICE_PASS");
    unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
    }
    loop {
        thread::park();
    }
}
