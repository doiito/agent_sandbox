//! Short control connections; the persistent actor owns every interpreter.
mod transport;
mod wire;

use crate::code_context::{self as code, Client, Context, Language, Manager, Response, State};
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
pub use wire::{Binding, PREFIX, PROTOCOL, Reply, Request};

pub const PORT: u32 = 5003;
const MAX_CONTROLS: usize = 4;
const IO_SLICE: Duration = Duration::from_millis(50);
const IO_TIMEOUT: Duration = Duration::from_secs(2);
pub type Acceptor = fn(RawFd, Instant) -> io::Result<Option<File>>;

#[derive(serde::Serialize)]
pub struct Readiness {
    pub revision: u32,
    pub kernel_protocol: &'static str,
    pub prewarm_language: Language,
}

enum Permission {
    Pending,
    Legacy {
        session_id: Option<String>,
        deadline: Instant,
    },
    Prepared {
        binding: Binding,
        deadline: Instant,
    },
    Revoked,
}
impl Permission {
    fn deadline(&self, hard: Instant) -> Instant {
        match self {
            Self::Legacy { deadline, .. } | Self::Prepared { deadline, .. } => {
                (*deadline).min(hard)
            }
            Self::Pending | Self::Revoked => hard,
        }
    }
    fn authorize(&mut self, request: &Request, hard: Instant) -> code::Result<Instant> {
        let deadline = self.deadline(hard);
        if Instant::now() >= deadline {
            return Err(wire::error("expired", "code service lease expired"));
        }
        match self {
            Self::Pending => {
                return Err(wire::error("unsupported", "code service is not authorized"));
            }
            Self::Revoked => return Err(wire::error("unavailable", "code service has stopped")),
            Self::Legacy { session_id, .. } if request.binding.is_none() => {
                if let Some(id) = session_id {
                    if id != &request.session_id {
                        return Err(wire::error(
                            "invalid_binding",
                            "code session identity mismatch",
                        ));
                    }
                } else {
                    *session_id = Some(request.session_id.clone());
                }
            }
            Self::Prepared { binding, .. }
                if request.binding.as_ref() == Some(binding)
                    && request.session_id == binding.session_id => {}
            _ => {
                return Err(wire::error(
                    "invalid_binding",
                    "code session binding mismatch",
                ));
            }
        }
        Ok(deadline)
    }
}
struct Control {
    stop: AtomicBool,
    active: AtomicUsize,
    permission: Mutex<Permission>,
    hard_deadline: Instant,
    client: Client,
}
impl Control {
    fn close(&self) {
        *self.permission.lock().unwrap() = Permission::Revoked;
        self.stop.store(true, Ordering::Release);
        self.client.stop();
    }
    fn deadline(&self) -> Instant {
        self.permission.lock().unwrap().deadline(self.hard_deadline)
    }
    fn dispatch(&self, request: &Request) -> code::Result<Response> {
        let deadline = self
            .permission
            .lock()
            .unwrap()
            .authorize(request, self.hard_deadline)?;
        self.client.request_until(request.request.clone(), deadline)
    }
}
struct Slot {
    control: Arc<Control>,
    done: mpsc::SyncSender<()>,
}
impl Drop for Slot {
    fn drop(&mut self) {
        self.control.active.fetch_sub(1, Ordering::AcqRel);
        let _ = self.done.try_send(());
    }
}

pub struct Service {
    control: Arc<Control>,
    thread: Option<JoinHandle<()>>,
    prewarmed: Option<Context>,
}
impl Service {
    pub fn start(
        listener: File,
        accept: Acceptor,
        options: code::Options,
        prewarm: Option<Language>,
    ) -> io::Result<Self> {
        if unsafe { libc::listen(listener.as_raw_fd(), (MAX_CONTROLS + 2) as i32) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let hard_deadline = options.hard_deadline;
        let manager = Manager::start(options)?;
        let client = manager.client();
        let prewarmed = prewarm
            .map(|language| warm(&client, language, hard_deadline))
            .transpose()?;
        let control = Arc::new(Control {
            stop: AtomicBool::new(false),
            active: AtomicUsize::new(0),
            permission: Mutex::new(Permission::Pending),
            hard_deadline,
            client,
        });
        let shared = control.clone();
        let thread = thread::Builder::new()
            .name("code-control".into())
            .spawn(move || {
                let mut workers: Vec<JoinHandle<()>> = Vec::new();
                let (done, completed) = mpsc::sync_channel(MAX_CONTROLS);
                while !shared.stop.load(Ordering::Acquire) && Instant::now() < shared.deadline() {
                    let mut index = 0;
                    while index < workers.len() {
                        if workers[index].is_finished() {
                            if workers.swap_remove(index).join().is_err() {
                                shared.close();
                            }
                        } else {
                            index += 1;
                        }
                    }
                    if shared.stop.load(Ordering::Acquire) {
                        break;
                    }
                    if workers.len() >= MAX_CONTROLS {
                        let _ = completed.recv_timeout(
                            IO_SLICE
                                .min(shared.deadline().saturating_duration_since(Instant::now())),
                        );
                        continue;
                    }
                    let until = (Instant::now() + IO_SLICE).min(shared.deadline());
                    let connection = match accept(listener.as_raw_fd(), until) {
                        Ok(Some(connection)) => connection,
                        Ok(None) => continue,
                        Err(_) => {
                            shared.close();
                            crate::workload::fail_closed();
                            break;
                        }
                    };
                    if shared.stop.load(Ordering::Acquire) || Instant::now() >= shared.deadline() {
                        break;
                    }
                    shared.active.fetch_add(1, Ordering::AcqRel);
                    let slot = Slot {
                        control: shared.clone(),
                        done: done.clone(),
                    };
                    match thread::Builder::new()
                        .name("code-rpc".into())
                        .spawn(move || {
                            transport::serve(connection, &slot.control);
                            drop(slot);
                        }) {
                        Ok(worker) => workers.push(worker),
                        Err(_) => {
                            shared.close();
                            crate::workload::fail_closed();
                            break;
                        }
                    }
                }
                shared.close();
                manager.shutdown();
                for worker in workers {
                    if worker.join().is_err() {
                        crate::workload::fail_closed();
                    }
                }
            })?;
        Ok(Self {
            control,
            thread: Some(thread),
            prewarmed,
        })
    }
    pub fn prewarmed_context(&self) -> Option<&Context> {
        self.prewarmed.as_ref()
    }
    pub fn readiness(&self) -> Option<Readiness> {
        let warm = self.prewarmed.as_ref()?;
        let Response::Context(current) = self
            .control
            .client
            .request(code::Request::Info {
                context_id: warm.id.clone(),
            })
            .ok()?
        else {
            return None;
        };
        (current.state == State::Idle && current.generation == warm.generation).then_some(
            Readiness {
                revision: 1,
                kernel_protocol: code::KERNEL_PROTOCOL,
                prewarm_language: current.language,
            },
        )
    }
    pub fn active_connections(&self) -> usize {
        self.control.active.load(Ordering::Acquire)
    }
    pub fn authorize_legacy(&self, deadline: Instant) -> io::Result<()> {
        let mut permission = self.control.permission.lock().unwrap();
        let deadline = deadline.min(self.control.hard_deadline);
        match &mut *permission {
            Permission::Pending if deadline > Instant::now() => {
                *permission = Permission::Legacy {
                    session_id: None,
                    deadline,
                }
            }
            Permission::Legacy { deadline: old, .. } => *old = (*old).min(deadline),
            _ => return Err(io::ErrorKind::PermissionDenied.into()),
        }
        Ok(())
    }
    pub fn authorize_prepared(&self, binding: Binding, deadline: Instant) -> io::Result<()> {
        if !binding.valid() || deadline <= Instant::now() {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut permission = self.control.permission.lock().unwrap();
        let deadline = deadline.min(self.control.hard_deadline);
        match &mut *permission {
            Permission::Pending => *permission = Permission::Prepared { binding, deadline },
            Permission::Prepared {
                binding: old_binding,
                deadline: old,
            } if *old_binding == binding => *old = (*old).min(deadline),
            _ => return Err(io::ErrorKind::PermissionDenied.into()),
        }
        Ok(())
    }
    pub fn revoke(&self) {
        self.control.close();
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.control.close();
        if let Some(thread) = self.thread.take()
            && thread.join().is_err()
        {
            crate::workload::fail_closed();
        }
    }
}
fn warm(client: &Client, language: Language, hard: Instant) -> io::Result<Context> {
    let deadline = (Instant::now() + Duration::from_secs(40)).min(hard);
    let Response::Context(mut context) = client
        .request(code::Request::Default { language })
        .map_err(io::Error::other)?
    else {
        return Err(io::Error::other("invalid prewarm response"));
    };
    loop {
        match context.state {
            State::Idle => return Ok(context),
            State::Starting if Instant::now() < deadline => {}
            _ => return Err(io::Error::other("interpreter failed to become ready")),
        }
        thread::sleep(Duration::from_millis(5));
        let Response::Context(next) = client
            .request_until(
                code::Request::Info {
                    context_id: context.id.clone(),
                },
                deadline,
            )
            .map_err(io::Error::other)?
        else {
            return Err(io::Error::other("invalid prewarm state"));
        };
        context = next;
    }
}

#[cfg(test)]
mod tests;
