use super::*;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{FromRawFd, IntoRawFd};
use std::os::unix::net::{UnixListener, UnixStream};

fn request() -> Request {
    Request {
        protocol: PROTOCOL.into(),
        session_id: "a".repeat(24),
        nonce: "b".repeat(64),
        binding: None,
        request: code::Request::List {},
    }
}
fn accept(listener: RawFd, deadline: Instant) -> io::Result<Option<File>> {
    let mut fd = libc::pollfd {
        fd: listener,
        events: libc::POLLIN,
        revents: 0,
    };
    let result = unsafe {
        libc::poll(
            &mut fd,
            1,
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis()
                .max(1) as i32,
        )
    };
    if result == 0 {
        return Ok(None);
    }
    if result < 0 {
        return Err(io::Error::last_os_error());
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
fn service(lifetime: Duration) -> (Service, std::path::PathBuf) {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let path = std::env::temp_dir().join(format!(
        "osv-code-service-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let listener = UnixListener::bind(&path).unwrap();
    let file = unsafe { File::from_raw_fd(listener.into_raw_fd()) };
    let service = Service::start(
        file,
        accept,
        code::Options::packaged(Instant::now() + lifetime),
        None,
    )
    .unwrap();
    (service, path)
}
fn rpc(path: &std::path::Path, request: &Request) -> Reply {
    let mut stream = UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    writeln!(stream, "{}", serde_json::to_string(request).unwrap()).unwrap();
    let mut reply = String::new();
    BufReader::new(stream).read_line(&mut reply).unwrap();
    serde_json::from_str(reply.strip_prefix(PREFIX).unwrap()).unwrap()
}
fn wait(predicate: impl Fn() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while !predicate() {
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(2));
    }
}
#[test]
fn pending_legacy_pinning_and_prepared_binding_are_distinct() {
    let hard = Instant::now() + Duration::from_secs(10);
    let mut request = request();
    assert_eq!(
        Permission::Pending
            .authorize(&request, hard)
            .unwrap_err()
            .code,
        "unsupported"
    );
    let mut permission = Permission::Legacy {
        session_id: None,
        deadline: hard,
    };
    assert!(permission.authorize(&request, hard).is_ok());
    request.session_id = "c".repeat(24);
    assert_eq!(
        permission.authorize(&request, hard).unwrap_err().code,
        "invalid_binding"
    );
    let binding = Binding {
        session_id: request.session_id.clone(),
        nonce: "d".repeat(64),
    };
    let mut permission = Permission::Prepared {
        binding: binding.clone(),
        deadline: hard,
    };
    assert_eq!(
        permission.authorize(&request, hard).unwrap_err().code,
        "invalid_binding"
    );
    request.binding = Some(binding);
    assert!(permission.authorize(&request, hard).is_ok());
    assert_eq!(
        permission
            .authorize(&request, Instant::now())
            .unwrap_err()
            .code,
        "expired"
    );
    assert_eq!(
        Permission::Revoked
            .authorize(&request, hard)
            .unwrap_err()
            .code,
        "unavailable"
    );
}
#[test]
fn strict_envelope_identity_and_typed_command_reject_bad_inputs() {
    let valid = serde_json::to_value(request()).unwrap();
    assert!(Request::parse(&serde_json::to_vec(&valid).unwrap()).is_ok());
    for (field, value) in [
        ("extra", serde_json::json!(true)),
        ("nonce", serde_json::json!("B".repeat(64))),
        ("session_id", serde_json::json!("a".repeat(23))),
        ("protocol", serde_json::json!("fc-code/v0")),
        ("request", serde_json::json!({"operation":"list","extra":1})),
        ("request", serde_json::json!({"operation":"shell"})),
    ] {
        let mut invalid = valid.clone();
        invalid[field] = value;
        assert!(Request::parse(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }
    assert!(Request::parse(&vec![b' '; wire::REQUEST_LIMIT + 1]).is_err());
}
#[test]
fn short_rpc_echoes_identity_and_revoke_is_permanent() {
    let (service, path) = service(Duration::from_secs(10));
    let client = service.control.client.clone();
    assert_eq!(rpc(&path, &request()).error.unwrap().code, "unsupported");
    service
        .authorize_legacy(Instant::now() + Duration::from_secs(8))
        .unwrap();
    let reply = rpc(&path, &request());
    assert_eq!(reply.protocol, PROTOCOL);
    assert_eq!(reply.nonce, request().nonce);
    assert_eq!(reply.session_id, request().session_id);
    assert!(matches!(reply.response,Some(Response::Contexts(ref contexts)) if contexts.is_empty()));
    let mut wrong = request();
    wrong.session_id = "c".repeat(24);
    assert_eq!(rpc(&path, &wrong).error.unwrap().code, "invalid_binding");
    service.revoke();
    assert!(
        service
            .authorize_legacy(Instant::now() + Duration::from_secs(8))
            .is_err()
    );
    drop(service);
    assert!(client.request(code::Request::List {}).is_err());
    std::fs::remove_file(path).unwrap();
}
#[test]
fn prepared_identity_cannot_be_rebound_and_no_connection_is_needed_for_expiry() {
    let (service, path) = service(Duration::from_secs(10));
    let mut request = request();
    let binding = Binding {
        session_id: request.session_id.clone(),
        nonce: "c".repeat(64),
    };
    service
        .authorize_prepared(binding.clone(), Instant::now() + Duration::from_millis(200))
        .unwrap();
    request.binding = Some(binding.clone());
    assert!(rpc(&path, &request).error.is_none());
    let mut other = binding;
    other.nonce = "d".repeat(64);
    assert!(
        service
            .authorize_prepared(other, Instant::now() + Duration::from_secs(1))
            .is_err()
    );
    wait(|| service.control.stop.load(Ordering::Acquire));
    assert!(
        service
            .control
            .client
            .request(code::Request::List {})
            .is_err()
    );
    drop(service);
    std::fs::remove_file(path).unwrap();
}
#[test]
fn four_physical_controls_backlog_replacement_and_partial_reader_shutdown() {
    let (service, path) = service(Duration::from_secs(10));
    service
        .authorize_legacy(Instant::now() + Duration::from_secs(8))
        .unwrap();
    let mut blockers: Vec<_> = (0..4)
        .map(|_| UnixStream::connect(&path).unwrap())
        .collect();
    wait(|| service.active_connections() == 4);
    let mut fifth = UnixStream::connect(&path).unwrap();
    fifth
        .set_read_timeout(Some(Duration::from_millis(50)))
        .unwrap();
    writeln!(fifth, "{}", serde_json::to_string(&request()).unwrap()).unwrap();
    let mut byte = [0];
    assert!(matches!(
        fifth.read(&mut byte).unwrap_err().kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ));
    drop(blockers.pop());
    fifth
        .set_read_timeout(Some(Duration::from_secs(2)))
        .unwrap();
    let mut reply = String::new();
    BufReader::new(fifth).read_line(&mut reply).unwrap();
    assert!(reply.starts_with(PREFIX));
    let start = Instant::now();
    drop(service);
    assert!(start.elapsed() < Duration::from_secs(1));
    drop(blockers);
    std::fs::remove_file(path).unwrap();
}
#[test]
fn expired_actor_call_does_not_consume_work_and_stop_wakes_it() {
    let manager = Manager::start(code::Options::packaged(
        Instant::now() + Duration::from_secs(10),
    ))
    .unwrap();
    let client = manager.client();
    assert_eq!(
        client
            .request_until(code::Request::List {}, Instant::now())
            .unwrap_err()
            .code,
        "expired"
    );
    assert!(
        matches!(client.request(code::Request::List {}).unwrap(),Response::Contexts(ref contexts) if contexts.is_empty())
    );
    client.stop();
    assert_eq!(
        client.request(code::Request::List {}).unwrap_err().code,
        "unavailable"
    );
    manager.shutdown();
}
