use super::inotify::{Engine, Event};
use crate::pristine::{Binding, Runtime};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(super) const PORT: u32 = 5002;
const PROTOCOL: &str = "fc-watch/v1";
const PREFIX: &[u8] = b"FC_WATCH_EVENT ";
const MAX_ACTIVE: usize = 4;
const MAX_REQUEST: usize = 8192;
const MAX_FRAME: usize = 32 * 1024;
const MAX_PENDING: usize = 64 * 1024;
const IO_SLICE: Duration = Duration::from_millis(100);
const IO_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
enum Permission {
    Disabled,
    Legacy(Instant),
    Prepared(Binding, Instant),
}

impl Permission {
    fn from_runtime(runtime: &Runtime, hard_deadline: Instant, legacy_session: bool) -> Self {
        match runtime {
            Runtime::Legacy if legacy_session => Self::Legacy(hard_deadline),
            Runtime::Prepared {
                binding,
                deadline,
                one_shot: false,
            } => Self::Prepared(binding.clone(), (*deadline).min(hard_deadline)),
            _ => Self::Disabled,
        }
    }
    fn deadline(&self, request: &Request) -> Result<Instant, &'static str> {
        let deadline = match self {
            Self::Disabled => return Err("unsupported"),
            Self::Legacy(deadline) if request.binding.is_none() => *deadline,
            Self::Prepared(binding, deadline)
                if request.binding.as_ref() == Some(binding)
                    && request.session_id == binding.session_id =>
            {
                *deadline
            }
            _ => return Err("invalid_binding"),
        };
        if Instant::now() >= deadline {
            Err("expired")
        } else {
            Ok(deadline)
        }
    }
}

struct Control {
    stop: AtomicBool,
    active: AtomicUsize,
    legacy_session: AtomicBool,
    permission: RwLock<Permission>,
}
struct Slot(Arc<Control>);
impl Drop for Slot {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::AcqRel);
    }
}
impl Control {
    fn acquire(self: &Arc<Self>) -> Option<Slot> {
        self.active
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_ACTIVE).then_some(n + 1)
            })
            .ok()?;
        Some(Slot(self.clone()))
    }
}

pub(crate) struct Service {
    control: Arc<Control>,
    thread: Option<JoinHandle<()>>,
}

impl Service {
    pub(crate) fn start(
        workspace: &Path,
        runtime: &Runtime,
        hard_deadline: Instant,
    ) -> io::Result<Self> {
        let raw = crate::listen_vsock(PORT)?;
        let listener = unsafe { File::from_raw_fd(raw) };
        if unsafe { libc::listen(raw, (MAX_ACTIVE + 2) as i32) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Self::with_listener(
            workspace,
            runtime,
            hard_deadline,
            listener,
            crate::accept_host_vsock_until,
        )
    }

    pub(crate) fn with_listener(
        workspace: &Path,
        runtime: &Runtime,
        hard_deadline: Instant,
        listener: File,
        accept: fn(RawFd, Instant) -> io::Result<Option<File>>,
    ) -> io::Result<Self> {
        let control = Arc::new(Control {
            stop: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            legacy_session: AtomicBool::new(false),
            permission: RwLock::new(Permission::from_runtime(runtime, hard_deadline, false)),
        });
        let shared = control.clone();
        let workspace = workspace.to_owned();
        let thread = thread::Builder::new()
            .name("workspace-watch".into())
            .spawn(move || {
                let mut workers: Vec<JoinHandle<()>> = vec![];
                while !shared.stop.load(Ordering::Acquire) && Instant::now() < hard_deadline {
                    let mut index = 0;
                    while index < workers.len() {
                        if workers[index].is_finished() {
                            let _ = workers.swap_remove(index).join();
                        } else {
                            index += 1;
                        }
                    }
                    // Do not accept and drop a new connection using a stale
                    // worker count. A released host watch may still be leaving
                    // its guest thread; keep its replacement in the bounded
                    // listener backlog until the physical worker is joined.
                    if workers.len() >= MAX_ACTIVE {
                        thread::sleep(
                            IO_SLICE.min(hard_deadline.saturating_duration_since(Instant::now())),
                        );
                        continue;
                    }
                    let connection = match accept(
                        listener.as_raw_fd(),
                        (Instant::now() + IO_SLICE).min(hard_deadline),
                    ) {
                        Ok(Some(file)) => file,
                        Ok(None) => continue,
                        Err(_) => break,
                    };
                    let Some(slot) = shared.acquire() else {
                        drop(connection);
                        continue;
                    };
                    let worker_control = shared.clone();
                    let worker_workspace = workspace.clone();
                    if let Ok(worker) = thread::Builder::new()
                        .name("directory-events".into())
                        .spawn(move || {
                            let _slot = slot;
                            serve(connection, &worker_workspace, &worker_control);
                        })
                    {
                        workers.push(worker);
                    }
                }
                shared.stop.store(true, Ordering::Release);
                for worker in workers {
                    let _ = worker.join();
                }
            })?;
        Ok(Self {
            control,
            thread: Some(thread),
        })
    }

    pub(crate) fn update(&self, runtime: &Runtime, hard_deadline: Instant) {
        *self.control.permission.write().unwrap() = Permission::from_runtime(
            runtime,
            hard_deadline,
            self.control.legacy_session.load(Ordering::Acquire),
        );
    }

    pub(crate) fn authorize_legacy_session(&self, hard_deadline: Instant) {
        self.control.legacy_session.store(true, Ordering::Release);
        *self.control.permission.write().unwrap() = Permission::Legacy(hard_deadline);
    }
}

impl Drop for Service {
    fn drop(&mut self) {
        self.control.stop.store(true, Ordering::Release);
        *self.control.permission.write().unwrap() = Permission::Disabled;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: String,
    session_id: String,
    watch_id: String,
    nonce: String,
    path: String,
    #[serde(default)]
    recursive: bool,
    #[serde(default)]
    include_entry: bool,
    #[serde(default)]
    binding: Option<Binding>,
    #[serde(default)]
    timeout_ms: u64,
}

#[derive(Serialize)]
struct Frame<'a> {
    protocol: &'static str,
    session_id: &'a str,
    watch_id: &'a str,
    nonce: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding: Option<&'a Binding>,
    kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    event: Option<&'a Event>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'static str>,
}

fn valid_hex(value: &str, count: usize) -> bool {
    value.len() == count
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn frame(
    request: &Request,
    kind: &'static str,
    event: Option<&Event>,
    code: Option<&'static str>,
) -> io::Result<Vec<u8>> {
    let mut bytes = PREFIX.to_vec();
    serde_json::to_writer(
        &mut bytes,
        &Frame {
            protocol: PROTOCOL,
            session_id: &request.session_id,
            watch_id: &request.watch_id,
            nonce: &request.nonce,
            binding: request.binding.as_ref(),
            kind,
            event,
            code,
        },
    )?;
    bytes.push(b'\n');
    if bytes.len() > MAX_FRAME {
        return Err(io::Error::from_raw_os_error(libc::E2BIG));
    }
    Ok(bytes)
}

fn read_request(connection: &mut File, control: &Control) -> io::Result<Request> {
    let deadline = Instant::now() + IO_TIMEOUT;
    let mut bytes = vec![];
    let mut part = [0u8; 1024];
    while !control.stop.load(Ordering::Acquire) && Instant::now() < deadline {
        let mut descriptor = libc::pollfd {
            fd: connection.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ready = unsafe { libc::poll(&mut descriptor, 1, IO_SLICE.as_millis() as i32) };
        if ready < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if ready == 0 {
            continue;
        }
        match connection.read(&mut part) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => bytes.extend_from_slice(&part[..count]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        }
        if bytes.len() > MAX_REQUEST {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if let Some(end) = bytes.iter().position(|byte| *byte == b'\n') {
            if end + 1 != bytes.len() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let request: Request = serde_json::from_slice(&bytes)?;
            if request.protocol != PROTOCOL
                || !valid_hex(&request.watch_id, 24)
                || !valid_hex(&request.session_id, 24)
                || !valid_hex(&request.nonce, 64)
                || request.timeout_ms > crate::SESSION_MAX_AGE.as_millis() as u64
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            return Ok(request);
        }
    }
    Err(io::ErrorKind::TimedOut.into())
}

fn serve(mut connection: File, workspace: &Path, control: &Control) {
    let flags = unsafe { libc::fcntl(connection.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe {
            libc::fcntl(
                connection.as_raw_fd(),
                libc::F_SETFL,
                flags | libc::O_NONBLOCK,
            )
        } < 0
    {
        return;
    }
    let Ok(request) = read_request(&mut connection, control) else {
        return;
    };
    let permission = control.permission.read().unwrap().clone();
    let initial_deadline = permission.deadline(&request);
    let started = Instant::now();
    let requested_deadline = if request.timeout_ms == 0 {
        None
    } else {
        Some(started + Duration::from_millis(request.timeout_ms))
    };
    let mut terminal = initial_deadline.err();
    let mut engine = if terminal.is_none() {
        match Engine::new(
            workspace,
            &request.path,
            request.recursive,
            request.include_entry,
        ) {
            Ok(engine) => Some(engine),
            Err(error) => {
                terminal = Some(error.code());
                None
            }
        }
    } else {
        None
    };
    let mut queue: VecDeque<Vec<u8>> = VecDeque::new();
    let mut queued_bytes = 0;
    if terminal.is_none() {
        let Ok(ready) = frame(&request, "ready", None, None) else {
            return;
        };
        queued_bytes += ready.len();
        queue.push_back(ready);
    }
    let mut terminal_queued = false;
    let mut offset = 0;
    let mut progress = Instant::now();
    loop {
        if control.stop.load(Ordering::Acquire) {
            return;
        }
        if terminal.is_none() {
            let policy = control.permission.read().unwrap().clone();
            match policy.deadline(&request) {
                Ok(deadline)
                    if Instant::now() >= requested_deadline.unwrap_or(deadline).min(deadline) =>
                {
                    terminal = Some("expired")
                }
                Ok(_) => {}
                Err(code) => terminal = Some(code),
            }
        }
        if terminal.is_some() {
            engine = None;
        }
        if !terminal_queued && let Some(code) = terminal {
            let Ok(end) = frame(&request, "end", None, Some(code)) else {
                return;
            };
            if queue.is_empty() {
                progress = Instant::now();
            }
            queued_bytes += end.len();
            queue.push_back(end);
            terminal_queued = true;
        }
        if terminal_queued && queue.is_empty() {
            return;
        }
        if !queue.is_empty() && progress.elapsed() >= IO_TIMEOUT {
            return;
        }
        let mut descriptors = [
            libc::pollfd {
                fd: connection.as_raw_fd(),
                events: libc::POLLIN | if queue.is_empty() { 0 } else { libc::POLLOUT },
                revents: 0,
            },
            libc::pollfd {
                fd: engine.as_ref().map_or(-1, Engine::raw_fd),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let status = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as libc::nfds_t,
                IO_SLICE.as_millis() as i32,
            )
        };
        if status < 0 {
            if io::Error::last_os_error().kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return;
        }
        if descriptors[0].revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL | libc::POLLIN)
            != 0
        {
            return;
        }
        if descriptors[0].revents & libc::POLLOUT != 0
            && let Some(front) = queue.front()
        {
            match connection.write(&front[offset..]) {
                Ok(0) => return,
                Ok(count) => {
                    offset += count;
                    progress = Instant::now();
                    if offset == front.len() {
                        queued_bytes -= front.len();
                        queue.pop_front();
                        offset = 0;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => return,
            }
        }
        if let Some(capture) = engine.as_mut() {
            // Also expire unresolved recursive moves when the event fd is idle.
            match capture.drain() {
                Ok(events) => {
                    for mut event in events {
                        let first = frame(&request, "event", Some(&event), None);
                        let encoded = match first.or_else(|error| {
                            if event.entry.is_none() {
                                return Err(error);
                            }
                            // EntryInfo is best effort; a large xattr map must
                            // not hide the actual filesystem event.
                            event.entry = None;
                            frame(&request, "event", Some(&event), None)
                        }) {
                            Ok(encoded) => encoded,
                            Err(_) => {
                                terminal = Some("operation_limit");
                                break;
                            }
                        };
                        if queued_bytes + encoded.len() > MAX_PENDING - 1024 {
                            terminal = Some("overflow");
                            break;
                        }
                        if queue.is_empty() {
                            progress = Instant::now();
                        }
                        queued_bytes += encoded.len();
                        queue.push_back(encoded);
                    }
                }
                Err(error) => terminal = Some(error.code()),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::{BufRead, BufReader};
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Tree(PathBuf);
    impl Tree {
        fn new() -> Self {
            let p = std::env::temp_dir().join(format!(
                "osv-watch-service-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&p).unwrap();
            Self(p)
        }
    }
    impl Drop for Tree {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    fn request() -> serde_json::Value {
        serde_json::json!({"protocol":PROTOCOL,"session_id":"0123456789abcdef01234567","watch_id":"abcdef0123456789abcdef01","nonce":"a".repeat(64),"path":"/workspace"})
    }
    fn launch(
        root: &Tree,
        permission: Permission,
    ) -> (
        UnixStream,
        BufReader<UnixStream>,
        Arc<Control>,
        JoinHandle<()>,
    ) {
        let (client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let control = Arc::new(Control {
            stop: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            legacy_session: AtomicBool::new(false),
            permission: RwLock::new(permission),
        });
        let slot = control.acquire().unwrap();
        let other = control.clone();
        let path = root.0.clone();
        let thread = thread::spawn(move || {
            let _slot = slot;
            let file = unsafe { File::from_raw_fd(server.into_raw_fd()) };
            serve(file, &path, &other);
        });
        let reader = BufReader::new(client.try_clone().unwrap());
        (client, reader, control, thread)
    }
    fn read(reader: &mut BufReader<UnixStream>) -> serde_json::Value {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).unwrap() > 0);
        serde_json::from_str(
            line.strip_prefix(std::str::from_utf8(PREFIX).unwrap())
                .unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn full_service_reuses_released_worker_capacity_without_dropping_new_connections() {
        fn accept_unix(fd: RawFd, deadline: Instant) -> io::Result<Option<File>> {
            let mut descriptor = libc::pollfd {
                fd,
                events: libc::POLLIN,
                revents: 0,
            };
            let timeout = deadline
                .saturating_duration_since(Instant::now())
                .as_millis()
                .min(i32::MAX as u128) as i32;
            let ready = unsafe { libc::poll(&mut descriptor, 1, timeout) };
            if ready < 0 {
                return Err(io::Error::last_os_error());
            }
            if ready == 0 {
                return Ok(None);
            }
            let raw = unsafe {
                libc::accept4(
                    fd,
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
        let root = Tree::new();
        let socket = root.0.join("service.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let listener = unsafe { File::from_raw_fd(listener.into_raw_fd()) };
        let hard = Instant::now() + Duration::from_secs(15);
        let service =
            Service::with_listener(&root.0, &Runtime::Legacy, hard, listener, accept_unix).unwrap();
        service.authorize_legacy_session(hard);
        let connect = || {
            let mut client = UnixStream::connect(&socket).unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            serde_json::to_writer(&mut client, &request()).unwrap();
            client.write_all(b"\n").unwrap();
            let mut reader = BufReader::new(client.try_clone().unwrap());
            assert_eq!(read(&mut reader)["kind"], "ready");
            client
        };
        let mut clients: Vec<_> = (0..MAX_ACTIVE).map(|_| connect()).collect();
        for _ in 0..16 {
            clients
                .pop()
                .unwrap()
                .shutdown(std::net::Shutdown::Both)
                .unwrap();
            clients.push(connect());
            assert_eq!(service.control.active.load(Ordering::Acquire), MAX_ACTIVE);
        }
        for client in clients {
            client.shutdown(std::net::Shutdown::Both).unwrap();
        }
        let control = service.control.clone();
        drop(service);
        assert_eq!(control.active.load(Ordering::Acquire), 0);
    }
    #[test]
    fn streams_real_events_and_peer_disconnect_releases_the_worker() {
        let root = Tree::new();
        let (mut client, mut reader, control, worker) = launch(
            &root,
            Permission::Legacy(Instant::now() + Duration::from_secs(5)),
        );
        serde_json::to_writer(&mut client, &request()).unwrap();
        client.write_all(b"\n").unwrap();
        assert_eq!(read(&mut reader)["kind"], "ready");
        fs::write(root.0.join("live"), b"event").unwrap();
        let event = read(&mut reader);
        assert_eq!(event["kind"], "event");
        assert_eq!(event["event"]["name"], "live");
        assert_eq!(event["event"]["sequence"], 1);
        client.shutdown(std::net::Shutdown::Both).unwrap();
        worker.join().unwrap();
        assert_eq!(control.active.load(Ordering::Acquire), 0);
    }
    #[test]
    fn pristine_and_mismatched_binding_never_start_an_inotify_subscription() {
        let root = Tree::new();
        for permission in [
            Permission::Disabled,
            Permission::Prepared(
                Binding {
                    session_id: "0123456789abcdef01234567".into(),
                    nonce: "b".repeat(64),
                },
                Instant::now() + Duration::from_secs(5),
            ),
        ] {
            let (mut client, mut reader, control, worker) = launch(&root, permission);
            serde_json::to_writer(&mut client, &request()).unwrap();
            client.write_all(b"\n").unwrap();
            let end = read(&mut reader);
            assert_eq!(end["kind"], "end");
            assert!(matches!(
                end["code"].as_str(),
                Some("unsupported" | "invalid_binding")
            ));
            worker.join().unwrap();
            assert_eq!(control.active.load(Ordering::Acquire), 0);
        }
    }
    #[test]
    fn prepared_binding_is_echoed_and_timeout_is_enforced_without_poll_requests() {
        let root = Tree::new();
        let binding = Binding {
            session_id: "0123456789abcdef01234567".into(),
            nonce: "b".repeat(64),
        };
        let (mut client, mut reader, control, worker) = launch(
            &root,
            Permission::Prepared(binding.clone(), Instant::now() + Duration::from_secs(5)),
        );
        let mut value = request();
        value["binding"] = serde_json::to_value(&binding).unwrap();
        value["timeout_ms"] = 50.into();
        serde_json::to_writer(&mut client, &value).unwrap();
        client.write_all(b"\n").unwrap();
        let ready = read(&mut reader);
        assert_eq!(ready["kind"], "ready");
        assert_eq!(ready["binding"], value["binding"]);
        let end = read(&mut reader);
        assert_eq!(end["kind"], "end");
        assert_eq!(end["code"], "expired");
        worker.join().unwrap();
        assert_eq!(control.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn idle_watch_delivers_its_expiry_after_the_write_idle_window() {
        let root = Tree::new();
        let (mut client, mut reader, control, worker) = launch(
            &root,
            Permission::Legacy(Instant::now() + Duration::from_secs(5)),
        );
        let mut value = request();
        value["timeout_ms"] = 2100.into();
        serde_json::to_writer(&mut client, &value).unwrap();
        client.write_all(b"\n").unwrap();
        assert_eq!(read(&mut reader)["kind"], "ready");
        let end = read(&mut reader);
        assert_eq!(end["code"], "expired");
        worker.join().unwrap();
        assert_eq!(control.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn policy_invalidation_stops_an_idle_subscription() {
        let root = Tree::new();
        let (mut client, mut reader, control, worker) = launch(
            &root,
            Permission::Legacy(Instant::now() + Duration::from_secs(5)),
        );
        serde_json::to_writer(&mut client, &request()).unwrap();
        client.write_all(b"\n").unwrap();
        assert_eq!(read(&mut reader)["kind"], "ready");
        *control.permission.write().unwrap() = Permission::Disabled;
        let end = read(&mut reader);
        assert_eq!(end["code"], "unsupported");
        worker.join().unwrap();
        assert_eq!(control.active.load(Ordering::Acquire), 0);
    }

    #[test]
    fn session_reply_publishes_authorization_before_the_host_can_start_watching() {
        for prepared in [false, true] {
            let hard = Instant::now() + Duration::from_secs(5);
            let binding = Binding {
                session_id: "0123456789abcdef01234567".into(),
                nonce: "b".repeat(64),
            };
            let mut runtime = if prepared {
                Runtime::Prepared {
                    binding: binding.clone(),
                    deadline: hard,
                    one_shot: false,
                }
            } else {
                Runtime::Legacy
            };
            let control = Arc::new(Control {
                stop: AtomicBool::new(false),
                active: AtomicUsize::new(0),
                legacy_session: AtomicBool::new(false),
                permission: RwLock::new(Permission::Disabled),
            });
            let service = Arc::new(Service {
                control: control.clone(),
                thread: None,
            });
            let (mut client, server) = UnixStream::pair().unwrap();
            client
                .set_read_timeout(Some(Duration::from_secs(2)))
                .unwrap();
            let server_service = service.clone();
            let worker = thread::spawn(move || {
                let connection = unsafe { File::from_raw_fd(server.into_raw_fd()) };
                crate::handle_connection_watch(
                    connection,
                    None,
                    hard,
                    &mut runtime,
                    Some(server_service.as_ref()),
                );
            });
            let ping = serde_json::json!({"protocol":if prepared{crate::pristine::PROTOCOL}else{crate::SESSION_PROTOCOL},"job_id":"1123456789abcdef01234567","operation":"ping","binding":if prepared{Some(binding.clone())}else{None}});
            serde_json::to_writer(&mut client, &ping).unwrap();
            client.write_all(b"\n").unwrap();
            let mut line = String::new();
            BufReader::new(client).read_line(&mut line).unwrap();
            assert!(line.starts_with(crate::RESULT_PREFIX));
            let mut watch = request();
            if prepared {
                watch["binding"] = serde_json::to_value(binding).unwrap();
            }
            let watch: Request = serde_json::from_value(watch).unwrap();
            assert!(
                control.permission.read().unwrap().deadline(&watch).is_ok(),
                "session ACK preceded watch permission"
            );
            worker.join().unwrap();
            drop(service);
        }
    }
}
