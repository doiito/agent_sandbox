//! Independently cancellable, bounded TCP connections to this guest's loopback.
mod relay;
#[cfg(test)]
mod tests;
pub mod wire;

use std::collections::BTreeMap;
use std::fs::File;
use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};
pub use wire::{Binding, Info, Limits, Request};

pub const PORT: u32 = 5004;
pub const MAX_CONNECTIONS: usize = 8;
pub const MAX_RECORDS: usize = 256;
const TCP_BUFFER_BYTES: libc::c_int = 64 * 1024;
const MAX_CONTROLS: usize = 4;
const SLICE: Duration = Duration::from_millis(25);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);
pub type Acceptor = fn(RawFd, Instant) -> io::Result<Option<File>>;

#[derive(Clone, Copy)]
pub struct Options {
    pub hard_deadline: Instant,
    pub max_connections: usize,
    pub max_records: usize,
}
impl Options {
    pub fn packaged(hard_deadline: Instant) -> Self {
        Self {
            hard_deadline,
            max_connections: MAX_CONNECTIONS,
            max_records: MAX_RECORDS,
        }
    }
    fn validate(self) -> io::Result<()> {
        if !(1..=MAX_CONNECTIONS).contains(&self.max_connections)
            || !(self.max_connections..=MAX_RECORDS).contains(&self.max_records)
            || self.hard_deadline <= Instant::now()
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        Ok(())
    }
}

enum Permission {
    Pending,
    Legacy {
        id: Option<String>,
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
    fn authorize(&mut self, r: &Request, hard: Instant) -> Result<Instant, &'static str> {
        let deadline = self.deadline(hard);
        if deadline <= Instant::now() {
            return Err("expired");
        }
        match self {
            Self::Legacy { id, .. } if r.binding.is_none() => match id {
                Some(id) if id != &r.session_id => return Err("invalid_binding"),
                None => *id = Some(r.session_id.clone()),
                _ => (),
            },
            Self::Prepared { binding, .. }
                if r.binding.as_ref() == Some(binding) && r.session_id == binding.session_id => {}
            Self::Pending => return Err("unsupported"),
            Self::Revoked => return Err("unavailable"),
            _ => return Err("invalid_binding"),
        }
        Ok(deadline)
    }
}

struct Flow {
    id: String,
    port: u16,
    cancel: AtomicBool,
    started: AtomicBool,
    sent: AtomicU64,
    received: AtomicU64,
    outcome: Mutex<Option<Option<&'static str>>>,
}
impl Flow {
    fn new(r: &Request) -> Self {
        Self {
            id: r.id.clone(),
            port: r.port,
            cancel: AtomicBool::new(false),
            started: AtomicBool::new(false),
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            outcome: Mutex::new(None),
        }
    }
    fn finish(&self, error: Option<&'static str>) {
        let mut outcome = self.outcome.lock().unwrap();
        if outcome.is_none() {
            *outcome = Some(error);
        }
    }
    fn info(&self) -> Info {
        let outcome = *self.outcome.lock().unwrap();
        let (status, error) = match outcome {
            Some(None) => ("completed", None),
            Some(Some(error @ ("cancelled" | "service_closed"))) => {
                ("cancelled", Some(error.into()))
            }
            Some(Some(error)) => ("failed", Some(error.into())),
            None if self.cancel.load(Ordering::Acquire) => ("cancelling", None),
            None if self.started.load(Ordering::Acquire) => ("open", None),
            None => ("opening", None),
        };
        Info {
            id: self.id.clone(),
            port: self.port,
            status: status.into(),
            sent_bytes: self.sent.load(Ordering::Acquire),
            received_bytes: self.received.load(Ordering::Acquire),
            error,
        }
    }
}

struct Control {
    stop: AtomicBool,
    permission: Mutex<Permission>,
    flows: Mutex<BTreeMap<String, Arc<Flow>>>,
    workers: Mutex<Vec<JoinHandle<()>>>,
    options: Options,
}
impl Control {
    fn deadline(&self) -> Instant {
        self.permission
            .lock()
            .unwrap()
            .deadline(self.options.hard_deadline)
    }
    fn authorize(&self, r: &Request) -> Result<Instant, &'static str> {
        if self.stop.load(Ordering::Acquire) {
            return Err("unavailable");
        }
        self.permission
            .lock()
            .unwrap()
            .authorize(r, self.options.hard_deadline)
    }
    fn revoke(&self) {
        self.stop.store(true, Ordering::Release);
        *self.permission.lock().unwrap() = Permission::Revoked;
    }
    fn reap(&self, workers: &mut Vec<JoinHandle<()>>) {
        let mut index = 0;
        while index < workers.len() {
            if workers[index].is_finished() {
                if workers.swap_remove(index).join().is_err() {
                    self.stop.store(true, Ordering::Release);
                }
            } else {
                index += 1;
            }
        }
    }
    fn inspect(&self, r: &Request) -> Result<Info, &'static str> {
        self.authorize(r)?;
        let mut flows = self.flows.lock().unwrap();
        if let Some(flow) = flows.get(&r.id) {
            if flow.port != r.port {
                return Err("invalid_binding");
            }
            if r.operation == "cancel" {
                flow.cancel.store(true, Ordering::Release);
            }
            return Ok(flow.info());
        }
        if r.operation == "info" {
            return Err("not_found");
        }
        if flows.len() >= self.options.max_records {
            return Err("quota");
        }
        let flow = Arc::new(Flow::new(r));
        flow.cancel.store(true, Ordering::Release);
        flow.finish(Some("cancelled"));
        let info = flow.info();
        flows.insert(r.id.clone(), flow);
        Ok(info)
    }
    fn open(self: &Arc<Self>, mut file: File, request: Request) {
        let result = (|| {
            let deadline = self.authorize(&request)?;
            let mut workers = self.workers.lock().unwrap();
            self.reap(&mut workers);
            if self.stop.load(Ordering::Acquire) {
                return Err("unavailable");
            }
            let mut flows = self.flows.lock().unwrap();
            if let Some(previous) = flows.get(&request.id) {
                return Err(if previous.port != request.port {
                    "invalid_binding"
                } else if previous.cancel.load(Ordering::Acquire) {
                    "cancelled"
                } else {
                    "conflict"
                });
            }
            if workers.len() >= self.options.max_connections
                || flows.len() >= self.options.max_records
            {
                return Err("quota");
            }
            let flow = Arc::new(Flow::new(&request));
            flows.insert(request.id.clone(), flow.clone());
            Ok((flow, deadline, workers))
        })();
        let (flow, deadline, mut workers) = match result {
            Ok(value) => value,
            Err(error) => {
                let _ = relay::reply(&mut file, &request, Err(error), self);
                return;
            }
        };
        let shared = self.clone();
        let owned = flow.clone();
        match thread::Builder::new()
            .name("port-data".into())
            .stack_size(256 * 1024)
            .spawn(move || relay::open(file, request, owned, shared, deadline))
        {
            Ok(worker) => workers.push(worker),
            Err(_) => flow.finish(Some("io_error")),
        }
    }
}

pub struct Service {
    control: Arc<Control>,
    listener: Option<JoinHandle<()>>,
}

#[derive(Debug, serde::Serialize)]
pub struct Readiness {
    pub revision: u32,
    pub protocol: &'static str,
    pub port: u32,
    pub target: &'static str,
    pub state: &'static str,
    pub max_connections: usize,
    pub max_records: usize,
    pub max_frame_bytes: usize,
    pub max_bytes: u64,
    pub max_duration_ms: u64,
}
impl Service {
    pub fn readiness(&self) -> Option<Readiness> {
        if self.control.stop.load(Ordering::Acquire) || self.listener.as_ref()?.is_finished() {
            return None;
        }
        let permission = self.control.permission.lock().unwrap();
        if permission.deadline(self.control.options.hard_deadline) <= Instant::now() {
            return None;
        }
        let state = match &*permission {
            Permission::Pending => "pending",
            Permission::Legacy { .. } | Permission::Prepared { .. } => "session",
            Permission::Revoked => return None,
        };
        Some(Readiness {
            revision: 1,
            protocol: wire::PROTOCOL,
            port: PORT,
            target: "ipv4_loopback",
            state,
            max_connections: self.control.options.max_connections,
            max_records: self.control.options.max_records,
            max_frame_bytes: wire::MAX_DATA,
            max_bytes: wire::MAX_BYTES,
            max_duration_ms: wire::MAX_DURATION_MS,
        })
    }
    /// The caller supplies a host-CID-only vsock acceptor in production.
    pub fn start(listener: File, accept: Acceptor, options: Options) -> io::Result<Self> {
        options.validate()?;
        if unsafe { libc::listen(listener.as_raw_fd(), (MAX_CONTROLS + 2) as i32) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let control = Arc::new(Control {
            stop: AtomicBool::new(false),
            permission: Mutex::new(Permission::Pending),
            flows: Mutex::new(BTreeMap::new()),
            workers: Mutex::new(Vec::new()),
            options,
        });
        let shared = control.clone();
        let listener = thread::Builder::new()
            .name("port-control".into())
            .spawn(move || {
                let mut controls: Vec<JoinHandle<()>> = Vec::new();
                while !shared.stop.load(Ordering::Acquire) && Instant::now() < shared.deadline() {
                    shared.reap(&mut controls);
                    shared.reap(&mut shared.workers.lock().unwrap());
                    if controls.len() >= MAX_CONTROLS {
                        thread::sleep(SLICE);
                        continue;
                    }
                    let connection = match accept(
                        listener.as_raw_fd(),
                        (Instant::now() + SLICE).min(shared.deadline()),
                    ) {
                        Ok(Some(value)) => value,
                        Ok(None) => continue,
                        Err(_) => {
                            shared.stop.store(true, Ordering::Release);
                            break;
                        }
                    };
                    let worker = shared.clone();
                    if let Ok(thread) = thread::Builder::new()
                        .name("port-request".into())
                        .stack_size(256 * 1024)
                        .spawn(move || relay::control(connection, worker))
                    {
                        controls.push(thread);
                    }
                }
                shared.revoke();
                for worker in controls {
                    let _ = worker.join();
                }
                for worker in shared.workers.lock().unwrap().drain(..) {
                    let _ = worker.join();
                }
            })?;
        Ok(Self {
            control,
            listener: Some(listener),
        })
    }
    pub fn authorize_prepared(&self, binding: Binding, deadline: Instant) -> io::Result<()> {
        if !binding.valid()
            || deadline <= Instant::now()
            || self.control.stop.load(Ordering::Acquire)
        {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let deadline = deadline.min(self.control.options.hard_deadline);
        let mut permission = self.control.permission.lock().unwrap();
        match &mut *permission {
            Permission::Pending => *permission = Permission::Prepared { binding, deadline },
            Permission::Prepared {
                binding: previous,
                deadline: old,
            } if previous == &binding => *old = (*old).min(deadline),
            _ => return Err(io::ErrorKind::PermissionDenied.into()),
        }
        Ok(())
    }
    pub fn authorize_legacy(&self, deadline: Instant) -> io::Result<()> {
        if deadline <= Instant::now() || self.control.stop.load(Ordering::Acquire) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let deadline = deadline.min(self.control.options.hard_deadline);
        let mut permission = self.control.permission.lock().unwrap();
        match &mut *permission {
            Permission::Pending => *permission = Permission::Legacy { id: None, deadline },
            Permission::Legacy { deadline: old, .. } => *old = (*old).min(deadline),
            _ => return Err(io::ErrorKind::PermissionDenied.into()),
        }
        Ok(())
    }
    pub fn revoke(&self) {
        self.control.revoke();
    }
    pub fn active_connections(&self) -> usize {
        self.control.workers.lock().unwrap().len()
    }
    pub fn close(&mut self) -> io::Result<()> {
        self.revoke();
        if let Some(listener) = self.listener.take() {
            listener
                .join()
                .map_err(|_| io::Error::other("port service thread failed"))?;
        }
        Ok(())
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
