use super::kernel::Kernel;
use super::wire::{EvalState, Frame};
use super::*;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::collections::{BTreeSet, VecDeque};
use std::fs;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Action {
    Fail,
    Restart,
    Remove,
}
struct Stop {
    action: Action,
    deadline: Instant,
}

struct Entry {
    info: Context,
    kernel: Option<Kernel>,
    ready: bool,
    startup_deadline: Instant,
    current: Option<String>,
    execution_deadline: Option<Instant>,
    interrupt: Option<(ExecutionStatus, Instant)>,
    signal_deadline: Option<Instant>,
    evaluation: Option<EvalState>,
    stop: Option<Stop>,
    count: u64,
    finished_count: u64,
    results: usize,
    result_bytes: usize,
    errored: bool,
    idle_bytes: usize,
}

impl Entry {
    fn start(id: String, language: Language, cwd: String, options: &Options) -> Self {
        let info = Context {
            id,
            generation: 1,
            language,
            cwd,
            state: State::Starting,
            pid: None,
            failure: None,
            discarded_late_events: 0,
            discarded_late_bytes: 0,
        };
        let mut entry = Self {
            info,
            kernel: None,
            ready: false,
            startup_deadline: Instant::now(),
            current: None,
            execution_deadline: None,
            interrupt: None,
            signal_deadline: None,
            evaluation: None,
            stop: None,
            count: 0,
            finished_count: 0,
            results: 0,
            result_bytes: 0,
            errored: false,
            idle_bytes: 0,
        };
        entry.launch(options);
        entry
    }
    fn launch(&mut self, options: &Options) {
        self.info.state = State::Starting;
        self.info.pid = None;
        self.info.failure = None;
        self.ready = false;
        self.count = 0;
        self.finished_count = 0;
        self.info.discarded_late_events = 0;
        self.info.discarded_late_bytes = 0;
        self.idle_bytes = 0;
        self.startup_deadline = Instant::now() + Duration::from_secs(30);
        match Kernel::spawn(&self.info, options) {
            Ok(kernel) => self.kernel = Some(kernel),
            Err(error) => {
                self.info.state = State::Failed;
                self.info.failure = Some(error.code);
            }
        }
    }
    fn checked(&self, generation: u64) -> Result<()> {
        if self.info.generation != generation {
            Err(Error::new("stale_context", "context generation changed"))
        } else {
            Ok(())
        }
    }
    fn halt(&mut self, action: Action, failure: Option<&str>) {
        if let Some(reason) = failure {
            self.info.failure = Some(reason.into());
        }
        if self.stop.is_none() {
            if let Some(kernel) = self.kernel.as_mut() {
                kernel.stop();
            }
            self.stop = Some(Stop {
                action,
                deadline: Instant::now() + STOP_GRACE,
            });
            self.info.state = State::Stopping;
        }
    }
    fn cancel(&mut self, status: ExecutionStatus) {
        if self.current.is_none() || self.interrupt.is_some() || self.stop.is_some() {
            return;
        }
        self.interrupt = Some((status, Instant::now() + INTERRUPT_GRACE));
        if let Some(kernel) = self.kernel.as_mut()
            && kernel.sent()
        {
            let sent = if self.info.language == Language::Python {
                kernel.interrupt()
            } else {
                self.signal_deadline = (self.evaluation == Some(EvalState::Evaluating))
                    .then(|| Instant::now() + Duration::from_millis(100));
                kernel.interrupt_frame(self.count)
            };
            if sent.is_ok() {
                self.info.state = State::Interrupting;
                return;
            }
        }
        self.halt(Action::Fail, Some("cancel_before_delivery"));
    }
    fn complete(
        &mut self,
        records: &mut BTreeMap<String, Record>,
        status: ExecutionStatus,
        usable: bool,
    ) -> Option<String> {
        let id = self.current.take()?;
        let record = records.get_mut(&id).unwrap();
        record.failure = self.info.failure.clone();
        record.finish(status, usable);
        self.execution_deadline = None;
        self.interrupt = None;
        self.signal_deadline = None;
        Some(id)
    }
    fn frame(&mut self, frame: Frame, records: &mut BTreeMap<String, Record>) -> Result<bool> {
        if let Some(bytes) = frame.late_output_size(self.finished_count) {
            self.discard_late(bytes)?;
            return Ok(false);
        }
        match frame {
            Frame::ExecutionState {
                execution_count,
                state,
            } if self.current.is_some()
                && execution_count == self.count
                && self.info.language != Language::Python
                && matches!(
                    (self.evaluation, state),
                    (None, EvalState::Evaluating)
                        | (Some(EvalState::Evaluating), EvalState::EventLoop)
                ) =>
            {
                self.evaluation = Some(state);
                if state == EvalState::EventLoop {
                    self.signal_deadline = None;
                } else if self.interrupt.is_some() {
                    self.signal_deadline = Some(Instant::now() + Duration::from_millis(100));
                }
            }
            Frame::InterruptAck { execution_count }
                if self.current.is_some()
                    && execution_count == self.count
                    && self.interrupt.is_some()
                    && self.info.language != Language::Python =>
            {
                self.signal_deadline = None;
            }
            Frame::Ready {
                protocol,
                language,
                version,
            } if self.info.state == State::Starting
                && !self.ready
                && protocol == super::wire::KERNEL_PROTOCOL
                && language == self.info.language
                && version == language.version() =>
            {
                self.ready = true
            }
            Frame::Result {
                data,
                is_main_result,
                execution_count,
            } if self.current.is_some() && !self.errored && execution_count == self.count => {
                let bytes = serde_json::to_vec(&data).unwrap().len();
                self.results += 1;
                self.result_bytes += bytes;
                if self.results > 16 || self.result_bytes > 32 * 1024 {
                    return Err(Error::new("output_limit", "rich result budget exceeded"));
                }
                records
                    .get_mut(self.current.as_ref().unwrap())
                    .unwrap()
                    .push(
                        Event::Result {
                            data,
                            is_main_result,
                        },
                        bytes,
                    )?;
            }
            Frame::Error {
                name,
                value,
                traceback,
                execution_count,
            } if self.current.is_some() && !self.errored && execution_count == self.count => {
                self.errored = true;
                let bytes = name.len() + value.len() + traceback.len();
                records
                    .get_mut(self.current.as_ref().unwrap())
                    .unwrap()
                    .push(
                        Event::Error {
                            name,
                            value,
                            traceback,
                        },
                        bytes,
                    )?;
            }
            Frame::Done { execution_count }
                if self.current.is_some() && execution_count == self.count =>
            {
                return Ok(true);
            }
            _ => {
                return Err(Error::new(
                    "kernel_protocol",
                    "invalid interpreter event order or identity",
                ));
            }
        }
        Ok(false)
    }
    fn discard_late(&mut self, bytes: usize) -> Result<()> {
        self.info.discarded_late_events = self.info.discarded_late_events.saturating_add(1);
        self.info.discarded_late_bytes = self.info.discarded_late_bytes.saturating_add(bytes);
        if self.info.discarded_late_events > EVENT_LIMIT
            || self.info.discarded_late_bytes > OUTPUT_LIMIT
        {
            return Err(Error::new(
                "late_output_limit",
                "closed execution output exceeds context budget",
            ));
        }
        Ok(())
    }
    fn tick(&mut self, records: &mut BTreeMap<String, Record>) -> Option<String> {
        let kernel = self.kernel.as_mut()?;
        let pump = kernel.pump(self.stop.is_some());
        self.info.pid = kernel.pid();
        let pump = match pump {
            Ok(value) => value,
            Err(error) => {
                self.halt(Action::Fail, Some(&error.code));
                if self
                    .stop
                    .as_ref()
                    .is_some_and(|stop| Instant::now() >= stop.deadline)
                {
                    crate::workload::fail_closed();
                }
                return None;
            }
        };
        if let Some(stop) = &self.stop {
            if pump.ended && self.kernel.as_ref().unwrap().clean() {
                self.kernel.take();
                self.info.pid = None;
                let status = self.interrupt.map_or(
                    if stop.action == Action::Fail {
                        ExecutionStatus::Failed
                    } else {
                        ExecutionStatus::Cancelled
                    },
                    |(status, _)| status,
                );
                return self.complete(records, status, false);
            }
            if Instant::now() >= stop.deadline {
                crate::workload::fail_closed();
            }
            return None;
        }
        if pump.ended || pump.control_closed {
            self.halt(Action::Fail, Some("kernel_exited"));
            return None;
        }
        for (stderr, bytes) in pump.output {
            if let Some(id) = self.current.as_ref() {
                let length = bytes.len();
                let data = STANDARD.encode(bytes);
                if let Err(error) = records.get_mut(id).unwrap().push(
                    if stderr {
                        Event::Stderr { data }
                    } else {
                        Event::Stdout { data }
                    },
                    length,
                ) {
                    self.halt(Action::Fail, Some(&error.code));
                    return None;
                }
            } else {
                self.idle_bytes = self.idle_bytes.saturating_add(bytes.len());
                if self.idle_bytes > OUTPUT_LIMIT {
                    self.halt(Action::Fail, Some("idle_output_limit"));
                    return None;
                }
            }
        }
        let mut done = false;
        for frame in pump.frames {
            if done {
                if let Some(bytes) = frame.late_output_size(self.count) {
                    if let Err(error) = self.discard_late(bytes) {
                        self.halt(Action::Fail, Some(&error.code));
                        break;
                    }
                    continue;
                }
                self.halt(Action::Fail, Some("kernel_protocol"));
                break;
            }
            match self.frame(frame, records) {
                Ok(finished) => done = finished,
                Err(error) => {
                    self.halt(Action::Fail, Some(&error.code));
                    break;
                }
            }
        }
        let completed = if done && self.stop.is_none() {
            self.finished_count = self.count;
            let status = self
                .interrupt
                .map_or(ExecutionStatus::Completed, |(status, _)| status);
            self.info.state = State::Idle;
            self.complete(records, status, true)
        } else {
            None
        };
        if self.ready && self.info.state == State::Starting && self.info.pid.is_some() {
            self.info.state = State::Idle;
        }
        let now = Instant::now();
        if self.info.state == State::Starting && now >= self.startup_deadline {
            self.halt(Action::Fail, Some("startup_timeout"));
        }
        if self.stop.is_none() && self.current.is_some() {
            if self.signal_deadline.is_some_and(|deadline| now >= deadline) {
                self.signal_deadline = None;
                if self.kernel.as_mut().unwrap().interrupt().is_err() {
                    self.halt(Action::Fail, Some("interrupt_failed"));
                }
            }
            if self.interrupt.is_some_and(|(_, deadline)| now >= deadline) {
                self.halt(Action::Fail, Some("interrupt_timeout"));
            } else if self
                .execution_deadline
                .is_some_and(|deadline| now >= deadline)
            {
                self.cancel(ExecutionStatus::TimedOut);
            }
        }
        completed
    }
}

pub(super) struct Actor {
    options: Options,
    contexts: BTreeMap<String, Entry>,
    defaults: BTreeMap<Language, String>,
    used: BTreeSet<String>,
    records: BTreeMap<String, Record>,
    completed: VecDeque<String>,
    next: u64,
}
impl Actor {
    pub fn new(options: Options) -> Self {
        Self {
            options,
            contexts: BTreeMap::new(),
            defaults: BTreeMap::new(),
            used: BTreeSet::new(),
            records: BTreeMap::new(),
            completed: VecDeque::new(),
            next: 1,
        }
    }
    fn create(&mut self, id: String, language: Language, cwd: String) -> Result<Response> {
        if let Some(entry) = self.contexts.get(&id) {
            if entry.info.language == language && entry.info.cwd == cwd {
                return Ok(Response::Context(entry.info.clone()));
            }
            return Err(Error::new(
                "conflict",
                "context ID already has another configuration",
            ));
        }
        if self.used.contains(&id) {
            return Err(Error::new("gone", "deleted context IDs cannot be reused"));
        }
        if self.contexts.len() >= MAX_CONTEXTS || self.used.len() >= MAX_TOTAL {
            return Err(Error::new("quota", "context quota exceeded"));
        }
        let directory = fs::canonicalize(&cwd)
            .map_err(|_| Error::new("invalid_request", "context cwd does not exist"))?;
        if !directory.starts_with("/workspace") || !directory.is_dir() {
            return Err(Error::new(
                "invalid_request",
                "context cwd must be within workspace",
            ));
        }
        let entry = Entry::start(id.clone(), language, cwd, &self.options);
        let response = Response::Context(entry.info.clone());
        self.used.insert(id.clone());
        self.contexts.insert(id, entry);
        Ok(response)
    }
    fn request(&mut self, request: Request) -> Result<Response> {
        match request {
            Request::Create {
                context_id,
                language,
                cwd,
            } => self.create(context_id, language, cwd),
            Request::Default { language } => {
                if let Some(id) = self.defaults.get(&language)
                    && let Some(entry) = self.contexts.get(id)
                {
                    return Ok(Response::Context(entry.info.clone()));
                }
                let id = loop {
                    let id = format!("d{:023x}", self.next);
                    self.next += 1;
                    if !self.used.contains(&id) {
                        break id;
                    }
                };
                let response = self.create(id.clone(), language, "/workspace".into())?;
                self.defaults.insert(language, id);
                Ok(response)
            }
            Request::List {} => Ok(Response::Contexts(
                self.contexts.values().map(|e| e.info.clone()).collect(),
            )),
            Request::Info { context_id } => Ok(Response::Context(
                self.contexts
                    .get(&context_id)
                    .ok_or_else(|| Error::new("not_found", "context not found"))?
                    .info
                    .clone(),
            )),
            Request::Execution {
                execution_id,
                after,
            } => Ok(Response::Execution(
                self.records
                    .get(&execution_id)
                    .ok_or_else(|| Error::new("not_found", "execution not found"))?
                    .page(after)?,
            )),
            Request::Execute {
                context_id,
                generation,
                execution_id,
                code,
                environment,
                timeout_ms,
            } => {
                if self.records.contains_key(&execution_id) {
                    return Err(Error::new(
                        "conflict",
                        "execution ID already used; query its record",
                    ));
                }
                if self.records.len() >= MAX_TOTAL {
                    return Err(Error::new("quota", "execution quota exceeded"));
                }
                let entry = self
                    .contexts
                    .get_mut(&context_id)
                    .ok_or_else(|| Error::new("not_found", "context not found"))?;
                entry.checked(generation)?;
                if entry.info.state != State::Idle {
                    return Err(Error::new(
                        "context_busy",
                        "context is not idle; failed contexts require restart",
                    ));
                }
                entry.kernel.as_mut().unwrap().submit(&code, &environment)?;
                entry.count += 1;
                entry.evaluation = None;
                entry.results = 0;
                entry.result_bytes = 0;
                entry.errored = false;
                entry.idle_bytes = 0;
                entry.execution_deadline =
                    (timeout_ms != 0).then(|| Instant::now() + Duration::from_millis(timeout_ms));
                entry.current = Some(execution_id.clone());
                entry.info.state = State::Running;
                let mut record = Record {
                    id: execution_id.clone(),
                    context_id,
                    generation,
                    status: ExecutionStatus::Running,
                    events: vec![],
                    sequence: 0,
                    bytes: 0,
                    evicted: false,
                    failure: None,
                };
                record.push(Event::Started, 0)?;
                self.records.insert(execution_id, record);
                Ok(Response::Accepted)
            }
            Request::Cancel {
                context_id,
                generation,
                execution_id,
            } => {
                let entry = self
                    .contexts
                    .get_mut(&context_id)
                    .ok_or_else(|| Error::new("not_found", "context not found"))?;
                entry.checked(generation)?;
                if !self.records.contains_key(&execution_id) {
                    if self.records.len() >= MAX_TOTAL {
                        return Err(Error::new("quota", "execution quota exceeded"));
                    }
                    let mut record = Record {
                        id: execution_id.clone(),
                        context_id,
                        generation,
                        status: ExecutionStatus::Running,
                        events: vec![],
                        sequence: 0,
                        bytes: 0,
                        evicted: false,
                        failure: Some("cancelled_before_submit".into()),
                    };
                    record.finish(
                        ExecutionStatus::Cancelled,
                        matches!(
                            entry.info.state,
                            State::Idle | State::Running | State::Interrupting
                        ),
                    );
                    self.records.insert(execution_id.clone(), record);
                    self.completed.push_back(execution_id);
                    return Ok(Response::Accepted);
                }
                let record = self
                    .records
                    .get(&execution_id)
                    .ok_or_else(|| Error::new("not_found", "execution not found"))?;
                if record.context_id != context_id || record.generation != generation {
                    return Err(Error::new(
                        "invalid_binding",
                        "execution belongs to another context",
                    ));
                }
                if entry.current.as_ref() == Some(&execution_id) {
                    entry.cancel(ExecutionStatus::Cancelled);
                }
                Ok(Response::Accepted)
            }
            Request::Restart {
                context_id,
                generation,
            } => self.lifecycle(context_id, generation, Action::Restart),
            Request::Remove {
                context_id,
                generation,
            } => self.lifecycle(context_id, generation, Action::Remove),
        }
    }
    fn lifecycle(&mut self, id: String, generation: u64, action: Action) -> Result<Response> {
        let entry = self
            .contexts
            .get_mut(&id)
            .ok_or_else(|| Error::new("not_found", "context not found"))?;
        entry.checked(generation)?;
        if entry
            .stop
            .as_ref()
            .is_some_and(|stop| stop.action != action)
        {
            return Err(Error::new(
                "context_busy",
                "context lifecycle operation is in progress",
            ));
        }
        entry.halt(action, None);
        Ok(if action == Action::Remove {
            Response::Removed
        } else {
            Response::Context(entry.info.clone())
        })
    }
    fn tick(&mut self) {
        let mut removed = Vec::new();
        for (id, entry) in &mut self.contexts {
            if let Some(execution) = entry.tick(&mut self.records) {
                self.completed.push_back(execution);
            }
            if entry.kernel.is_none()
                && let Some(stop) = entry.stop.take()
            {
                match stop.action {
                    Action::Fail => entry.info.state = State::Failed,
                    Action::Restart => {
                        entry.info.generation = entry
                            .info
                            .generation
                            .checked_add(1)
                            .expect("context generation overflow");
                        entry.launch(&self.options);
                    }
                    Action::Remove => removed.push(id.clone()),
                }
            }
        }
        for id in removed {
            self.contexts.remove(&id);
        }
        while self.completed.len() > 16 {
            let record = self
                .records
                .get_mut(&self.completed.pop_front().unwrap())
                .unwrap();
            record.events = Vec::new();
            record.evicted = true;
        }
    }
    fn wait(&self, wake: &Wake, stopping: bool) {
        let mut fds = vec![libc::pollfd {
            fd: wake.0.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        }];
        let mut deadline = if stopping {
            Instant::now() + STOP_GRACE
        } else {
            self.options.hard_deadline
        };
        for entry in self.contexts.values() {
            if let Some(kernel) = entry.kernel.as_ref() {
                kernel.poll_fds(&mut fds);
            } else if entry.stop.is_some() {
                deadline = Instant::now();
            }
            if entry.info.state == State::Starting {
                deadline = deadline.min(entry.startup_deadline);
            }
            if let Some(stop) = entry.stop.as_ref() {
                deadline = deadline.min(stop.deadline);
                continue;
            }
            if let Some((_, end)) = entry.interrupt {
                deadline = deadline.min(end);
            }
            if let Some(end) = entry.signal_deadline {
                deadline = deadline.min(end);
            }
            // An execution already being cancelled keeps the fixed grace,
            // rather than spinning on its expired original deadline.
            if entry.interrupt.is_none()
                && let Some(end) = entry.execution_deadline
            {
                deadline = deadline.min(end);
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        let timeout = if remaining.is_zero() {
            0
        } else {
            remaining.as_millis().clamp(1, i32::MAX as u128) as i32
        };
        if unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, timeout) } < 0
            && std::io::Error::last_os_error().kind() != std::io::ErrorKind::Interrupted
        {
            crate::workload::fail_closed();
        }
    }
    pub fn run(
        mut self,
        receive: mpsc::Receiver<Envelope>,
        stop: Arc<AtomicBool>,
        wake: Arc<Wake>,
    ) {
        loop {
            wake.drain();
            let stopping =
                stop.load(Ordering::Acquire) || Instant::now() >= self.options.hard_deadline;
            if stopping {
                for entry in self.contexts.values_mut() {
                    if let Some(pending) = entry.stop.as_mut() {
                        pending.action = Action::Remove;
                    } else {
                        entry.halt(Action::Remove, None);
                    }
                }
            }
            self.tick();
            if crate::workload::unusable() {
                break;
            }
            if stopping && self.contexts.is_empty() {
                break;
            }
            if !stopping {
                for _ in 0..16 {
                    match receive.try_recv() {
                        Ok(envelope) => {
                            let response = if Instant::now() >= envelope.deadline
                                || Instant::now() >= self.options.hard_deadline
                                || stop.load(Ordering::Acquire)
                            {
                                Err(Error::new("expired", "queued code request expired"))
                            } else {
                                self.request(envelope.request)
                            };
                            let _ = envelope.reply.try_send(response);
                        }
                        Err(mpsc::TryRecvError::Empty) => break,
                        Err(mpsc::TryRecvError::Disconnected) => {
                            stop.store(true, Ordering::Release);
                            break;
                        }
                    }
                }
            }
            self.wait(&wake, stopping);
        }
    }
}
