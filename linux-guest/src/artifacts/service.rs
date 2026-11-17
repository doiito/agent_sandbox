use super::{
    Result,
    tree::{Entry, Snapshot},
};
use crate::pristine::{Binding, Runtime};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::path::Path;
use std::sync::{
    Arc, RwLock,
    atomic::{AtomicBool, Ordering},
};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

pub(crate) const PORT: u32 = 5005;
const PROTOCOL: &str = "fc-artifact/v1";
const PREFIX: &[u8] = b"FC_ARTIFACT_EVENT ";
const IO_SLICE: Duration = Duration::from_millis(50);
const IO_TIMEOUT: Duration = Duration::from_secs(2);
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_REQUEST: usize = 8192;
const MAX_FRAME: usize = 128 << 10;
const MAX_FRAMES: u32 = 4096;

#[derive(Clone)]
enum Permission {
    Disabled,
    Legacy(Instant),
    Prepared(Binding, Instant),
}
impl Permission {
    fn from_runtime(runtime: &Runtime, hard: Instant, legacy: bool) -> Self {
        match runtime {
            Runtime::Legacy if legacy => Self::Legacy(hard),
            Runtime::Prepared {
                binding,
                deadline,
                one_shot: false,
            } => Self::Prepared(binding.clone(), (*deadline).min(hard)),
            _ => Self::Disabled,
        }
    }
    fn deadline(&self, request: &Request) -> Result<Instant> {
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
    legacy: AtomicBool,
    permission: RwLock<Permission>,
}

pub(crate) struct Service {
    control: Arc<Control>,
    thread: Option<JoinHandle<()>>,
}
impl Service {
    pub fn start(workspace: &Path, runtime: &Runtime, hard: Instant) -> io::Result<Self> {
        let listener = unsafe { File::from_raw_fd(crate::listen_vsock(PORT)?) };
        if unsafe { libc::listen(listener.as_raw_fd(), 2) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Self::with_listener(
            workspace,
            runtime,
            hard,
            listener,
            crate::accept_host_vsock_until,
        )
    }

    pub(super) fn with_listener(
        workspace: &Path,
        runtime: &Runtime,
        hard: Instant,
        listener: File,
        accept: fn(RawFd, Instant) -> io::Result<Option<File>>,
    ) -> io::Result<Self> {
        let control = Arc::new(Control {
            stop: AtomicBool::new(false),
            legacy: AtomicBool::new(false),
            permission: RwLock::new(Permission::from_runtime(runtime, hard, false)),
        });
        let shared = control.clone();
        let workspace = workspace.to_owned();
        // This thread handles one transfer at a time. A bounded listener
        // backlog holds replacements; no detached or unreaped workers exist.
        let thread = thread::Builder::new()
            .name("workspace-artifacts".into())
            .spawn(move || {
                while !shared.stop.load(Ordering::Acquire) && Instant::now() < hard {
                    match accept(listener.as_raw_fd(), (Instant::now() + IO_SLICE).min(hard)) {
                        Ok(Some(connection)) => serve(connection, &workspace, &shared, hard),
                        Ok(None) => (),
                        Err(_) => break,
                    }
                }
            })?;
        Ok(Self {
            control,
            thread: Some(thread),
        })
    }

    pub fn update(&self, runtime: &Runtime, hard: Instant) {
        *self.control.permission.write().unwrap() =
            Permission::from_runtime(runtime, hard, self.control.legacy.load(Ordering::Acquire));
    }
    pub fn authorize_legacy_session(&self, hard: Instant) {
        self.control.legacy.store(true, Ordering::Release);
        *self.control.permission.write().unwrap() = Permission::Legacy(hard);
    }
    pub fn revoke(&self) {
        self.control.legacy.store(false, Ordering::Release);
        *self.control.permission.write().unwrap() = Permission::Disabled;
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.control.stop.store(true, Ordering::Release);
        self.revoke();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    protocol: String,
    session_id: String,
    artifact_id: String,
    nonce: String,
    path: String,
    #[serde(default)]
    binding: Option<Binding>,
}
fn valid_hex(value: &str, count: usize) -> bool {
    value.len() == count
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

#[derive(Serialize)]
struct Totals {
    entries: usize,
    files: usize,
    payload_bytes: u64,
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Payload<'a> {
    Ready {
        path: &'a str,
        source_kind: &'a str,
    },
    Entry {
        entry: &'a Entry,
    },
    Data {
        offset: u64,
        data_base64: &'a str,
    },
    FileEnd {
        offset: u64,
    },
    End {
        #[serde(skip_serializing_if = "Option::is_none")]
        totals: Option<Totals>,
        #[serde(skip_serializing_if = "Option::is_none")]
        code: Option<&'a str>,
    },
}
#[derive(Serialize)]
struct Frame<'a> {
    protocol: &'static str,
    session_id: &'a str,
    artifact_id: &'a str,
    nonce: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding: Option<&'a Binding>,
    sequence: u32,
    #[serde(flatten)]
    payload: Payload<'a>,
}

fn poll(raw: RawFd, events: i16, wait: Duration) -> io::Result<i16> {
    let mut item = libc::pollfd {
        fd: raw,
        events,
        revents: 0,
    };
    let status = unsafe { libc::poll(&mut item, 1, wait.as_millis().min(i32::MAX as u128) as i32) };
    if status < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
            return Ok(0);
        }
        return Err(error);
    }
    Ok(item.revents)
}

fn read_request(connection: &mut File, control: &Control, hard: Instant) -> io::Result<Request> {
    let deadline = (Instant::now() + IO_TIMEOUT).min(hard);
    let mut bytes = Vec::new();
    let mut buffer = [0u8; 1024];
    while !control.stop.load(Ordering::Acquire) && Instant::now() < deadline {
        if poll(connection.as_raw_fd(), libc::POLLIN, IO_SLICE)? == 0 {
            continue;
        }
        match connection.read(&mut buffer) {
            Ok(0) => return Err(io::ErrorKind::UnexpectedEof.into()),
            Ok(count) => bytes.extend_from_slice(&buffer[..count]),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) => return Err(error),
        }
        if bytes.len() > MAX_REQUEST {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if let Some(end) = bytes.iter().position(|b| *b == b'\n') {
            if end + 1 != bytes.len() {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let request: Request = serde_json::from_slice(&bytes)?;
            if request.protocol != PROTOCOL
                || !valid_hex(&request.session_id, 24)
                || !valid_hex(&request.artifact_id, 24)
                || !valid_hex(&request.nonce, 64)
            {
                return Err(io::ErrorKind::InvalidData.into());
            }
            return Ok(request);
        }
    }
    Err(io::ErrorKind::TimedOut.into())
}

struct Guard<'a> {
    control: &'a Control,
    request: &'a Request,
    raw: RawFd,
    deadline: Instant,
}
impl Guard<'_> {
    fn check(&self) -> Result<()> {
        if self.control.stop.load(Ordering::Acquire) {
            return Err("expired");
        }
        let deadline = self
            .control
            .permission
            .read()
            .unwrap()
            .deadline(self.request)?;
        if Instant::now() >= deadline.min(self.deadline) {
            return Err("expired");
        }
        // A second request or peer EOF aborts the transfer immediately.
        if poll(self.raw, libc::POLLIN, Duration::ZERO).map_err(|_| "io_error")? != 0 {
            return Err("io_error");
        }
        Ok(())
    }
}
struct Sender<'a> {
    connection: &'a mut File,
    guard: &'a Guard<'a>,
    sequence: u32,
}
impl Sender<'_> {
    fn send(&mut self, payload: Payload<'_>, authorize: bool) -> Result<()> {
        if self.sequence >= MAX_FRAMES {
            return Err("operation_limit");
        }
        let request = self.guard.request;
        let mut bytes = PREFIX.to_vec();
        serde_json::to_writer(
            &mut bytes,
            &Frame {
                protocol: PROTOCOL,
                session_id: &request.session_id,
                artifact_id: &request.artifact_id,
                nonce: &request.nonce,
                binding: request.binding.as_ref(),
                sequence: self.sequence,
                payload,
            },
        )
        .map_err(|_| "io_error")?;
        bytes.push(b'\n');
        if bytes.len() > MAX_FRAME {
            return Err("operation_limit");
        }
        let mut offset = 0;
        let mut progress = Instant::now();
        while offset < bytes.len() {
            if authorize {
                self.guard.check()?;
            }
            if self.guard.control.stop.load(Ordering::Acquire) || progress.elapsed() >= IO_TIMEOUT {
                return Err("io_error");
            }
            let events = poll(self.connection.as_raw_fd(), libc::POLLOUT, IO_SLICE)
                .map_err(|_| "io_error")?;
            if events & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                return Err("io_error");
            }
            if events & libc::POLLOUT == 0 {
                continue;
            }
            match self.connection.write(&bytes[offset..]) {
                Ok(0) => return Err("io_error"),
                Ok(count) => {
                    offset += count;
                    progress = Instant::now();
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
                    ) =>
                {}
                Err(_) => return Err("io_error"),
            }
        }
        self.sequence += 1;
        Ok(())
    }
}

fn export(workspace: &Path, guard: &Guard<'_>, sender: &mut Sender<'_>) -> Result<()> {
    let mut check = || guard.check();
    check()?;
    let snapshot = Snapshot::capture(workspace, &guard.request.path, &mut check)?;
    sender.send(
        Payload::Ready {
            path: &guard.request.path,
            source_kind: snapshot.kind(),
        },
        true,
    )?;
    for entry in snapshot.entries() {
        check()?;
        sender.send(Payload::Entry { entry }, true)?;
        if entry.kind == "file" {
            snapshot.read_file(entry, &mut check, |offset, bytes| {
                sender.send(
                    Payload::Data {
                        offset,
                        data_base64: &STANDARD.encode(bytes),
                    },
                    true,
                )
            })?;
            sender.send(Payload::FileEnd { offset: entry.size }, true)?;
        }
    }
    snapshot.verify(&mut check)?;
    sender.send(
        Payload::End {
            totals: Some(Totals {
                entries: snapshot.count(),
                files: snapshot.files(),
                payload_bytes: snapshot.payload_bytes(),
            }),
            code: None,
        },
        true,
    )
}

fn serve(mut connection: File, workspace: &Path, control: &Control, hard: Instant) {
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
    let Ok(request) = read_request(&mut connection, control, hard) else {
        return;
    };
    let guard = Guard {
        control,
        request: &request,
        raw: connection.as_raw_fd(),
        deadline: (Instant::now() + TRANSFER_TIMEOUT).min(hard),
    };
    let mut sender = Sender {
        connection: &mut connection,
        guard: &guard,
        sequence: 0,
    };
    if let Err(code) = export(workspace, &guard, &mut sender) {
        // An error after a partial frame cannot form a valid transcript. The
        // host refuses it; this best effort terminal never publishes a tar.
        let _ = sender.send(
            Payload::End {
                totals: None,
                code: Some(code),
            },
            false,
        );
    }
}
