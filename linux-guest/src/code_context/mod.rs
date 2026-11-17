//! Persistent interpreter ownership; public transport/session authorization is separate.
mod actor;
mod kernel;
mod wire;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::os::fd::{AsRawFd, FromRawFd};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

const MAX_CONTEXTS: usize = 4;
pub const KERNEL_PROTOCOL: &str = wire::KERNEL_PROTOCOL;
const MAX_TOTAL: usize = 256;
const OUTPUT_LIMIT: usize = 64 * 1024;
const EVENT_LIMIT: usize = 256;
const CALL_TIMEOUT: Duration = Duration::from_secs(2);
const INTERRUPT_GRACE: Duration = Duration::from_millis(500);
const STOP_GRACE: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Language {
    Python,
    Javascript,
    Typescript,
}
impl Language {
    pub fn name(self) -> &'static str {
        match self {
            Self::Python => "python",
            Self::Javascript => "javascript",
            Self::Typescript => "typescript",
        }
    }
    fn version(self) -> &'static str {
        if self == Self::Python {
            "3.12.16"
        } else {
            "22.23.4"
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Starting,
    Idle,
    Running,
    Interrupting,
    Stopping,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Context {
    pub id: String,
    pub generation: u64,
    pub language: Language,
    pub cwd: String,
    pub state: State,
    pub pid: Option<u32>,
    pub failure: Option<String>,
    pub discarded_late_events: usize,
    pub discarded_late_bytes: usize,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionStatus {
    Running,
    Completed,
    Cancelled,
    TimedOut,
    Failed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    Started,
    Stdout {
        data: String,
    },
    Stderr {
        data: String,
    },
    Result {
        data: BTreeMap<String, Value>,
        is_main_result: bool,
    },
    Error {
        name: String,
        value: String,
        traceback: String,
    },
    Finished {
        status: ExecutionStatus,
        context_usable: bool,
    },
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct SequencedEvent {
    pub sequence: u64,
    pub event: Event,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ExecutionPage {
    pub id: String,
    pub context_id: String,
    pub generation: u64,
    pub status: ExecutionStatus,
    pub events: Vec<SequencedEvent>,
    pub last_sequence: u64,
    pub next_sequence: u64,
    pub events_evicted: bool,
    pub failure: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum Request {
    Create {
        context_id: String,
        language: Language,
        cwd: String,
    },
    Default {
        language: Language,
    },
    List {},
    Info {
        context_id: String,
    },
    Execute {
        context_id: String,
        generation: u64,
        execution_id: String,
        code: String,
        environment: BTreeMap<String, String>,
        timeout_ms: u64,
    },
    Execution {
        execution_id: String,
        after: u64,
    },
    Cancel {
        context_id: String,
        generation: u64,
        execution_id: String,
    },
    Restart {
        context_id: String,
        generation: u64,
    },
    Remove {
        context_id: String,
        generation: u64,
    },
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum Response {
    Context(Context),
    Contexts(Vec<Context>),
    Execution(ExecutionPage),
    Accepted,
    Removed,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Error {
    pub code: String,
    pub message: String,
}
impl Error {
    fn new(code: &str, message: &str) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

/// Trusted image paths and hard VM lifetime; never populated from tenant input.
pub struct Options {
    pub kernel_directory: PathBuf,
    pub hard_deadline: Instant,
}
impl Options {
    pub fn packaged(hard_deadline: Instant) -> Self {
        Self {
            kernel_directory: PathBuf::from("/opt/osv/code-kernels"),
            hard_deadline,
        }
    }
}

struct Envelope {
    request: Request,
    deadline: Instant,
    reply: mpsc::SyncSender<Result<Response>>,
}
struct Wake(File);
impl Wake {
    fn new() -> std::io::Result<Self> {
        let fd = unsafe { libc::eventfd(0, libc::EFD_CLOEXEC | libc::EFD_NONBLOCK) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(Self(unsafe { File::from_raw_fd(fd) }))
    }
    fn notify(&self) {
        let value = 1u64;
        loop {
            let result =
                unsafe { libc::write(self.0.as_raw_fd(), (&value as *const u64).cast(), 8) };
            if result >= 0
                || std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
            {
                break;
            }
        }
    }
    fn drain(&self) {
        let mut value = 0u64;
        loop {
            if unsafe { libc::read(self.0.as_raw_fd(), (&mut value as *mut u64).cast(), 8) } >= 0 {
                continue;
            }
            if std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted {
                break;
            }
        }
    }
}
#[derive(Clone)]
pub struct Client {
    commands: mpsc::SyncSender<Envelope>,
    wake: Arc<Wake>,
    stop: Arc<AtomicBool>,
}
impl Client {
    pub fn request(&self, request: Request) -> Result<Response> {
        self.request_until(request, Instant::now() + CALL_TIMEOUT)
    }
    pub(crate) fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        self.wake.notify();
    }
    pub(crate) fn request_until(&self, request: Request, lease: Instant) -> Result<Response> {
        wire::validate_request(&request)?;
        if self.stop.load(Ordering::Acquire) {
            return Err(Error::new("unavailable", "code worker has stopped"));
        }
        let (reply, receive) = mpsc::sync_channel(1);
        let deadline = lease.min(Instant::now() + CALL_TIMEOUT);
        if Instant::now() >= deadline {
            return Err(Error::new("expired", "code request lease expired"));
        }
        self.commands
            .try_send(Envelope {
                request,
                deadline,
                reply,
            })
            .map_err(|error| match error {
                mpsc::TrySendError::Full(_) => Error::new("busy", "code command queue is full"),
                mpsc::TrySendError::Disconnected(_) => {
                    Error::new("unavailable", "code worker has stopped")
                }
            })?;
        self.wake.notify();
        receive
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|_| {
                Error::new(
                    "unavailable",
                    "code worker response unavailable; query the known operation ID",
                )
            })?
    }
}

pub struct Manager {
    client: Client,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}
impl Manager {
    pub fn start(options: Options) -> std::io::Result<Self> {
        if Instant::now() >= options.hard_deadline || !options.kernel_directory.is_absolute() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "invalid code worker options",
            ));
        }
        let (commands, receive) = mpsc::sync_channel(16);
        let stop = Arc::new(AtomicBool::new(false));
        let worker_stop = stop.clone();
        let wake = Arc::new(Wake::new()?);
        let worker_wake = wake.clone();
        let thread = thread::Builder::new()
            .name("code-contexts".into())
            .spawn(move || {
                actor::Actor::new(options).run(receive, worker_stop, worker_wake);
            })?;
        Ok(Self {
            client: Client {
                commands,
                wake,
                stop: stop.clone(),
            },
            stop,
            thread: Some(thread),
        })
    }
    pub fn client(&self) -> Client {
        self.client.clone()
    }
    pub fn shutdown(mut self) {
        self.close();
    }
    fn close(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.client.wake.notify();
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            crate::workload::fail_closed();
        }
    }
}
impl Drop for Manager {
    fn drop(&mut self) {
        self.close();
    }
}

struct Record {
    id: String,
    context_id: String,
    generation: u64,
    status: ExecutionStatus,
    events: Vec<SequencedEvent>,
    sequence: u64,
    bytes: usize,
    evicted: bool,
    failure: Option<String>,
}
impl Record {
    fn push(&mut self, event: Event, bytes: usize) -> Result<()> {
        if self.events.len() >= EVENT_LIMIT - 1 || self.bytes.saturating_add(bytes) > OUTPUT_LIMIT {
            return Err(Error::new("output_limit", "code output budget exceeded"));
        }
        self.bytes += bytes;
        self.append(event);
        Ok(())
    }
    fn append(&mut self, event: Event) {
        self.sequence += 1;
        self.events.push(SequencedEvent {
            sequence: self.sequence,
            event,
        });
    }
    fn finish(&mut self, status: ExecutionStatus, usable: bool) {
        assert_eq!(self.status, ExecutionStatus::Running);
        self.status = status;
        self.append(Event::Finished {
            status,
            context_usable: usable,
        });
    }
    fn page(&self, after: u64) -> Result<ExecutionPage> {
        if after > self.sequence {
            return Err(Error::new(
                "invalid_cursor",
                "execution cursor exceeds last sequence",
            ));
        }
        let events: Vec<_> = self
            .events
            .iter()
            .filter(|e| e.sequence > after)
            .take(64)
            .cloned()
            .collect();
        let next = events.last().map_or(after, |e| e.sequence);
        Ok(ExecutionPage {
            id: self.id.clone(),
            context_id: self.context_id.clone(),
            generation: self.generation,
            status: self.status,
            events,
            last_sequence: self.sequence,
            next_sequence: next,
            events_evicted: self.evicted && after < self.sequence,
            failure: self.failure.clone(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn idle_actor_wakes_for_commands_and_shutdown_without_waiting_for_lease() {
        let manager =
            Manager::start(Options::packaged(Instant::now() + Duration::from_secs(30))).unwrap();
        let client = manager.client();
        for _ in 0..3 {
            assert!(
                matches!(client.request(Request::List {}).unwrap(),Response::Contexts(contexts) if contexts.is_empty())
            );
            thread::sleep(Duration::from_millis(10));
        }
        manager.shutdown();
        assert_eq!(
            client.request(Request::List {}).unwrap_err().code,
            "unavailable"
        );
    }
}
