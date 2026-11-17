//! Private per-workload cgroup/subreaper supervision; no guest-wide kill/reap.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::CString;
use std::fs::{self, File, Permissions};
use std::io::{self, Read, Write};
use std::marker::PhantomData;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixStream;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus, Stdio};
use std::rc::Rc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

const ROOT: &str = "/run/osv-workloads";
pub const SUPERVISOR_PATH: &str = "/sbin/osv-workload-supervisor";
const CONTROL: RawFd = 9;
const GROUP: RawFd = 10;
const KERNEL_INPUT: RawFd = 11;
const KERNEL_OUTPUT: RawFd = 12;
const PRIVATE_PROTOCOL: &str = "osv-workload-control/v1";
const CONFIG_LIMIT: usize = 512 * 1024;
const EVENT_LIMIT: usize = 2048;
const CLEANUP: Duration = Duration::from_millis(250);
const CGROUP2_MAGIC: libc::c_long = 0x63677270;
static NEXT: AtomicU64 = AtomicU64::new(1);
static UNUSABLE: AtomicBool = AtomicBool::new(false);
static FAILURE_HANDLER: OnceLock<fn() -> !> = OnceLock::new();

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Spec {
    pub argv: Vec<String>,
    pub environment: BTreeMap<String, String>,
    pub cwd: String,
}

impl Spec {
    pub fn validate(&self) -> io::Result<()> {
        if self.argv.is_empty()
            || self.argv.len() > 65
            || self.argv[0].is_empty()
            || self.argv.iter().any(|s| s.len() > 4096 || s.contains('\0'))
            || self.argv.iter().map(String::len).sum::<usize>() > 32 * 1024
            || !self.cwd.starts_with('/')
            || self.cwd.len() > 1024
            || self.cwd.chars().any(char::is_control)
            || self.environment.len() > 64
            || self.environment.iter().any(|(k, v)| {
                k.is_empty()
                    || k.len() > 64
                    || v.len() > 8192
                    || v.contains('\0')
                    || !k.bytes().enumerate().all(|(i, b)| {
                        b == b'_' || b.is_ascii_alphabetic() || i > 0 && b.is_ascii_digit()
                    })
            })
            || self
                .environment
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
                > 16 * 1024
        {
            return Err(invalid("invalid workload specification"));
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    protocol: String,
    spec: Spec,
    kernel_control: bool,
}

/// Nonblocking worker endpoints; the interpreter gets blocking fd3/fd4.
pub struct KernelIo {
    pub input: File,
    pub output: File,
}

fn pipe() -> io::Result<(File, File)> {
    let mut descriptors = [-1; 2];
    if unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe {
        (
            File::from_raw_fd(descriptors[0]),
            File::from_raw_fd(descriptors[1]),
        )
    })
}

fn nonblocking(file: &File) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0
        || unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Event {
    Started { pid: u32 },
    Exited { status: i32 },
    SpawnFailed { message: String },
    CancelledBeforeStart,
    Complete { status: i32 },
    Failed { message: String },
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub fn unusable() -> bool {
    UNUSABLE.load(Ordering::Acquire)
}

pub(crate) fn fail_closed() {
    poison();
}

fn poison() {
    UNUSABLE.store(true, Ordering::Release);
    if let Some(handler) = FAILURE_HANDLER.get() {
        handler();
    }
}

/// Production PID1 installs VM reset; the isolated validator observes poisoning.
pub fn install_failure_handler(handler: fn() -> !) -> io::Result<()> {
    require_owner()?;
    FAILURE_HANDLER
        .set(handler)
        .map_err(|_| invalid("VM failure handler already installed"))
}

fn require_owner() -> io::Result<()> {
    if unsafe { libc::getpid() } != 1 || unsafe { libc::geteuid() } != 0 || unusable() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "workload owner must be usable guest PID 1",
        ));
    }
    Ok(())
}

fn open_at(directory: &File, name: &str, flags: i32) -> io::Result<File> {
    let name = CString::new(name).map_err(|_| invalid("invalid cgroup filename"))?;
    let fd = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn directory(path: &Path) -> io::Result<File> {
    let name = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|_| invalid("invalid cgroup path"))?;
    let fd = unsafe {
        libc::open(
            name.as_ptr(),
            libc::O_DIRECTORY | libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn check_group(dir: &File) -> io::Result<()> {
    let mut info = std::mem::MaybeUninit::<libc::statfs>::uninit();
    if unsafe { libc::fstatfs(dir.as_raw_fd(), info.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let metadata = dir.metadata()?;
    if unsafe { info.assume_init() }.f_type as libc::c_long != CGROUP2_MAGIC
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
    {
        return Err(invalid("workload directory is not a root-owned cgroup v2"));
    }
    Ok(())
}

fn kill_group(dir: &File) -> io::Result<()> {
    open_at(dir, "cgroup.kill", libc::O_WRONLY)?.write_all(b"1")
}

fn empty_group(dir: &File) -> io::Result<bool> {
    let mut events = String::new();
    open_at(dir, "cgroup.events", libc::O_RDONLY)?
        .take(4096)
        .read_to_string(&mut events)?;
    if events.lines().any(|line| line == "populated 0") {
        return Ok(true);
    }
    if events.lines().any(|line| line == "populated 1") {
        return Ok(false);
    }
    Err(invalid("cgroup population state missing"))
}

pub fn initialize() -> io::Result<()> {
    require_owner()?;
    let helper = fs::symlink_metadata(SUPERVISOR_PATH)?;
    if !helper.is_file()
        || helper.uid() != 0
        || helper.mode() & 0o6022 != 0
        || helper.mode() & 0o100 == 0
        || helper.len() == 0
        || helper.len() > 4 * 1024 * 1024
    {
        return Err(invalid(
            "workload supervisor must be a root-owned executable",
        ));
    }
    // Populate immutable executable pages before advertising ready. A fresh
    // pooled VM has not executed this short-lived helper yet. Keep the read
    // bounded and off the allocator heap; no tenant code is run.
    {
        let mut executable = File::open(SUPERVISOR_PATH)?;
        let mut remaining = helper.len();
        let mut buffer = [0_u8; 16 * 1024];
        while remaining != 0 {
            let limit = remaining.min(buffer.len() as u64) as usize;
            match executable.read(&mut buffer[..limit]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "supervisor code truncated",
                    ));
                }
                Ok(count) => remaining -= count as u64,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }
    fs::create_dir_all(ROOT)?;
    let target = CString::new(ROOT).unwrap();
    let kind = c"cgroup2";
    if unsafe {
        libc::mount(
            kind.as_ptr(),
            target.as_ptr(),
            kind.as_ptr(),
            libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
            std::ptr::null(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    fs::set_permissions(ROOT, Permissions::from_mode(0o700))?;
    let root = directory(Path::new(ROOT))?;
    check_group(&root)?;
    let probe = Group::create()?;
    kill_group(&probe.dir)?;
    probe.finish()
}

struct Group {
    dir: File,
    path: PathBuf,
    removed: bool,
}

impl Group {
    fn create() -> io::Result<Self> {
        let path = Path::new(ROOT).join(format!("w{:016x}", NEXT.fetch_add(1, Ordering::Relaxed)));
        fs::create_dir(&path)?;
        fs::set_permissions(&path, Permissions::from_mode(0o700))?;
        let dir = directory(&path)?;
        check_group(&dir)?;
        Ok(Self {
            dir,
            path,
            removed: false,
        })
    }
    fn finish(mut self) -> io::Result<()> {
        if !empty_group(&self.dir)? {
            return Err(invalid("workload cgroup still populated"));
        }
        fs::remove_dir(&self.path)?;
        self.removed = true;
        Ok(())
    }
}

impl Drop for Group {
    fn drop(&mut self) {
        if !self.removed {
            let _ = kill_group(&self.dir);
            if empty_group(&self.dir).unwrap_or(false) {
                let _ = fs::remove_dir(&self.path);
            }
        }
    }
}

fn duplicate(fd: RawFd) -> io::Result<File> {
    let copy = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 64) };
    if copy < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(copy) })
}

fn pidfd(pid: u32) -> io::Result<File> {
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid as libc::pid_t, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd as RawFd) })
}

fn signal_pidfd(fd: &File, signal: i32) -> io::Result<()> {
    if unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            fd.as_raw_fd(),
            signal,
            std::ptr::null::<libc::siginfo_t>(),
            0,
        )
    } < 0
    {
        let error = io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    Ok(())
}

fn packet<T: Serialize>(value: &T, limit: usize) -> io::Result<Vec<u8>> {
    let data = serde_json::to_vec(value)?;
    if data.is_empty() || data.len() > limit {
        return Err(invalid("private control packet exceeds limit"));
    }
    let mut output = Vec::with_capacity(data.len() + 4);
    output.extend_from_slice(&(data.len() as u32).to_be_bytes());
    output.extend_from_slice(&data);
    Ok(output)
}

/// Must remain on its creating thread because Linux PDEATHSIG names that thread.
/// ```compile_fail,E0277
/// use firecracker_linux_agent::workload::Process;
/// fn migrate(process: Process) { std::thread::spawn(move || drop(process)); }
/// ```
pub struct Process {
    _creator_thread: PhantomData<Rc<()>>,
    helper: Child,
    helper_pidfd: File,
    control: UnixStream,
    group: Option<Group>,
    pending: Vec<u8>,
    sent: usize,
    received: Vec<u8>,
    pid: Option<u32>,
    no_start: bool,
    spawn_error: Option<String>,
    status: Option<ExitStatus>,
    observed_status: Option<ExitStatus>,
    helper_status: Option<ExitStatus>,
    stopped: bool,
    clean: bool,
    pub stdin: Option<ChildStdin>,
    pub stdout: Option<ChildStdout>,
    pub stderr: Option<ChildStderr>,
}

impl Process {
    pub fn spawn(spec: Spec, input: bool) -> io::Result<Self> {
        Self::spawn_inner(spec, input, None)
    }

    pub fn spawn_kernel(spec: Spec) -> io::Result<(Self, KernelIo)> {
        let (child_input, input) = pipe()?;
        let (output, child_output) = pipe()?;
        nonblocking(&input)?;
        nonblocking(&output)?;
        let process = Self::spawn_inner(spec, false, Some((child_input, child_output)))?;
        Ok((process, KernelIo { input, output }))
    }

    fn spawn_inner(spec: Spec, input: bool, kernel: Option<(File, File)>) -> io::Result<Self> {
        require_owner()?;
        spec.validate()?;
        let pending = packet(
            &Configuration {
                protocol: PRIVATE_PROTOCOL.into(),
                spec,
                kernel_control: kernel.is_some(),
            },
            CONFIG_LIMIT,
        )?;
        let group = Group::create()?;
        let (control, helper_control) = UnixStream::pair()?;
        control.set_nonblocking(true)?;
        let channel = duplicate(helper_control.as_raw_fd())?;
        let member = duplicate(group.dir.as_raw_fd())?;
        let control_fd = channel.as_raw_fd();
        let group_fd = member.as_raw_fd();
        let extras = kernel
            .as_ref()
            .map(|(input, output)| {
                Ok::<_, io::Error>((
                    duplicate(input.as_raw_fd())?,
                    duplicate(output.as_raw_fd())?,
                ))
            })
            .transpose()?;
        let extra_fds = extras
            .as_ref()
            .map(|(input, output)| (input.as_raw_fd(), output.as_raw_fd()));
        let mut command = Command::new(SUPERVISOR_PATH);
        command
            .arg("--workload-supervisor")
            .env_clear()
            .env("LANG", "C.UTF-8")
            .stdin(if input { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(move || {
                if libc::dup2(control_fd, CONTROL) < 0
                    || libc::dup2(group_fd, GROUP) < 0
                    || libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) < 0
                    || libc::getppid() != 1
                {
                    return Err(io::Error::last_os_error());
                }
                if let Some((input, output)) = extra_fds
                    && (libc::dup2(input, KERNEL_INPUT) < 0
                        || libc::dup2(output, KERNEL_OUTPUT) < 0)
                {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut helper = command.spawn()?;
        let helper_pidfd = match pidfd(helper.id()) {
            Ok(fd) => fd,
            Err(error) => {
                poison();
                let _ = kill_group(&group.dir);
                let _ = helper.kill(); // Still unreaped, therefore cannot target a reused PID.
                let _ = helper.wait();
                return Err(error);
            }
        };
        drop(helper_control);
        Ok(Self {
            _creator_thread: PhantomData,
            stdin: helper.stdin.take(),
            stdout: helper.stdout.take(),
            stderr: helper.stderr.take(),
            helper,
            helper_pidfd,
            control,
            group: Some(group),
            pending,
            sent: 0,
            received: Vec::new(),
            pid: None,
            no_start: false,
            spawn_error: None,
            status: None,
            observed_status: None,
            helper_status: None,
            stopped: false,
            clean: false,
        })
    }

    pub fn pid(&self) -> Option<u32> {
        self.pid
    }
    pub fn spawn_error(&self) -> Option<&str> {
        self.spawn_error.as_deref()
    }
    pub fn control_fd(&self) -> RawFd {
        self.control.as_raw_fd()
    }
    pub fn wants_write(&self) -> bool {
        self.sent < self.pending.len()
    }
    pub fn clean(&self) -> bool {
        self.clean
    }
    pub fn observed_status(&self) -> Option<ExitStatus> {
        self.observed_status
    }

    pub fn stop(&mut self) {
        if !self.stopped
            && !self.no_start
            && self.status.is_none()
            && self.observed_status.is_none()
        {
            self.pending.push(b'!');
            self.stopped = true;
        }
    }

    pub fn interrupt(&mut self) -> io::Result<()> {
        if self.pid.is_none()
            || self.status.is_some()
            || self.observed_status.is_some()
            || self.stopped
        {
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "workload is not interruptible",
            ));
        }
        if self.pending.len().saturating_sub(self.sent) >= 64 {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "workload control budget",
            ));
        }
        self.pending.push(b'I');
        Ok(())
    }

    fn event(&mut self, event: Event) -> io::Result<()> {
        if self.status.is_some() {
            return Err(invalid("control event after completion"));
        }
        match event {
            Event::Started { pid } if self.pid.is_none() && !self.no_start && pid > 1 => {
                self.pid = Some(pid)
            }
            Event::Exited { status }
                if self.pid.is_some()
                    && self.observed_status.is_none()
                    && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) =>
            {
                self.observed_status = Some(ExitStatus::from_raw(status));
            }
            Event::SpawnFailed { message }
                if self.pid.is_none() && !self.no_start && message.len() <= 1024 =>
            {
                self.no_start = true;
                self.spawn_error = Some(message);
            }
            Event::CancelledBeforeStart if self.pid.is_none() && !self.no_start => {
                self.no_start = true
            }
            Event::Complete { status }
                if (self
                    .observed_status
                    .is_some_and(|old| old.into_raw() == status)
                    || self.no_start)
                    && (libc::WIFEXITED(status) || libc::WIFSIGNALED(status)) =>
            {
                self.status = Some(ExitStatus::from_raw(status));
            }
            Event::Failed { .. } => return Err(invalid("workload supervisor reported failure")),
            _ => return Err(invalid("invalid workload control transition")),
        }
        Ok(())
    }

    fn progress(&mut self) -> io::Result<Option<ExitStatus>> {
        let mut buffer = [0u8; 4096];
        let mut eof = false;
        for _ in 0..8 {
            match self.control.read(&mut buffer) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(count) => self.received.extend_from_slice(&buffer[..count]),
                Err(error)
                    if error.kind() == io::ErrorKind::ConnectionReset && self.status.is_some() =>
                {
                    // A late stop can remain unread when the helper closes.
                    // Complete is already validated; still require clean exit
                    // and an empty cgroup below before reporting completion.
                    eof = true;
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
            while self.received.len() >= 4 {
                let size = u32::from_be_bytes(self.received[..4].try_into().unwrap()) as usize;
                if size == 0 || size > EVENT_LIMIT {
                    return Err(invalid("oversized workload event"));
                }
                if self.received.len() < size + 4 {
                    break;
                }
                let event: Event = serde_json::from_slice(&self.received[4..4 + size])?;
                self.received.drain(..4 + size);
                self.event(event)?;
            }
            if self.received.len() > EVENT_LIMIT + 4 {
                return Err(invalid("workload control buffer exceeded"));
            }
        }
        if self.helper_status.is_none() {
            self.helper_status = self.helper.try_wait()?;
        }
        if eof && self.status.is_none() {
            return Err(invalid("workload supervisor exited without cleanup ACK"));
        }
        if eof && !self.received.is_empty() {
            return Err(invalid("truncated workload control event"));
        }
        if self.observed_status.is_some() || self.status.is_some() {
            self.pending.clear();
            self.sent = 0;
        }
        while self.sent < self.pending.len() {
            match self.control.write(&self.pending[self.sent..]) {
                Ok(0) => return Err(invalid("workload control write closed")),
                Ok(count) => self.sent += count,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::BrokenPipe
                    ) =>
                {
                    break;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
        if let Some(status) = self.helper_status {
            if !status.success() {
                return Err(invalid("workload supervisor did not exit successfully"));
            }
            if eof && self.status.is_some() {
                if let Some(group) = self.group.take() {
                    group.finish()?;
                }
                self.clean = true;
                return Ok(self.status);
            }
        }
        Ok(None)
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        match self.progress() {
            Ok(status) => Ok(status),
            Err(error) => {
                poison();
                if let Some(group) = &self.group {
                    let _ = kill_group(&group.dir);
                }
                let _ = signal_pidfd(&self.helper_pidfd, libc::SIGKILL);
                Err(error)
            }
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if !self.clean {
            poison();
            if let Some(group) = &self.group {
                let _ = kill_group(&group.dir);
            }
            let _ = signal_pidfd(&self.helper_pidfd, libc::SIGKILL);
            let _ = self.helper.wait();
        }
    }
}

fn send(control: &mut UnixStream, event: &Event) -> io::Result<()> {
    control.write_all(&packet(event, EVENT_LIMIT)?)
}

fn receive_spec(control: &mut UnixStream) -> io::Result<Configuration> {
    let mut header = [0; 4];
    control.read_exact(&mut header)?;
    let size = u32::from_be_bytes(header) as usize;
    if size == 0 || size > CONFIG_LIMIT {
        return Err(invalid("invalid workload config frame"));
    }
    let mut body = vec![0; size];
    control.read_exact(&mut body)?;
    let configuration: Configuration = serde_json::from_slice(&body)?;
    if configuration.protocol != PRIVATE_PROTOCOL {
        return Err(invalid("private workload protocol mismatch"));
    }
    configuration.spec.validate()?;
    Ok(configuration)
}

enum Action {
    None,
    Stop,
    Interrupt,
}

fn action(control: &mut UnixStream) -> io::Result<Action> {
    let mut byte = [0u8; 1];
    match control.read(&mut byte) {
        Ok(0) => Ok(Action::Stop),
        Ok(1) if byte[0] == b'!' => Ok(Action::Stop),
        Ok(1) if byte[0] == b'I' => Ok(Action::Interrupt),
        Ok(_) => Err(invalid("invalid workload stop request")),
        Err(error)
            if error.kind() == io::ErrorKind::WouldBlock
                || error.kind() == io::ErrorKind::Interrupted =>
        {
            Ok(Action::None)
        }
        Err(error) => Err(error),
    }
}

fn reserve_kernel_io() -> io::Result<(File, File)> {
    // Occupy 3/4 BEFORE Command::spawn allocates its private exec error pipe.
    for descriptor in [3, 4] {
        if unsafe { libc::fcntl(descriptor, libc::F_GETFD) } >= 0 {
            return Err(invalid("kernel control descriptor already occupied"));
        }
        if io::Error::last_os_error().raw_os_error() != Some(libc::EBADF) {
            return Err(io::Error::last_os_error());
        }
    }
    for (descriptor, access) in [
        (KERNEL_INPUT, libc::O_RDONLY),
        (KERNEL_OUTPUT, libc::O_WRONLY),
    ] {
        let mut info = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::fstat(descriptor, info.as_mut_ptr()) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let info = unsafe { info.assume_init() };
        let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
        if flags < 0
            || info.st_mode & libc::S_IFMT != libc::S_IFIFO
            || flags & libc::O_ACCMODE != access
        {
            return Err(invalid(
                "kernel transport is not the expected directional pipe",
            ));
        }
    }
    if unsafe { libc::dup3(KERNEL_INPUT, 3, libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let input = unsafe { File::from_raw_fd(3) };
    if unsafe { libc::dup3(KERNEL_OUTPUT, 4, libc::O_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let output = unsafe { File::from_raw_fd(4) };
    // These originals are no longer needed; only 3/4 survive the user exec.
    unsafe {
        libc::close(KERNEL_INPUT);
        libc::close(KERNEL_OUTPUT);
    }
    Ok((input, output))
}

fn child_command(spec: Spec, dir: &File, kernel_control: bool) -> io::Result<(Command, File)> {
    let mut command = Command::new(&spec.argv[0]);
    command
        .args(&spec.argv[1..])
        .env_clear()
        .envs(spec.environment)
        .current_dir("/workspace")
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let cwd = CString::new(spec.cwd).map_err(|_| invalid("invalid workload cwd"))?;
    let procs = open_at(dir, "cgroup.procs", libc::O_WRONLY)?;
    let group_fd = procs.as_raw_fd();
    unsafe {
        command.pre_exec(move || {
            if libc::write(group_fd, b"0".as_ptr().cast(), 1) != 1 || libc::setsid() < 0 {
                return Err(io::Error::last_os_error());
            }
            for (resource, maximum) in [
                (libc::RLIMIT_CORE, 0),
                (libc::RLIMIT_NOFILE, 128),
                (libc::RLIMIT_NPROC, 64),
                (libc::RLIMIT_FSIZE, 64 * 1024 * 1024),
            ] {
                let limit = libc::rlimit {
                    rlim_cur: maximum,
                    rlim_max: maximum,
                };
                if libc::setrlimit(resource, &limit) < 0 {
                    return Err(io::Error::last_os_error());
                }
            }
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0
                || libc::setgroups(0, std::ptr::null()) < 0
                || libc::setgid(10000) < 0
                || libc::setuid(10000) < 0
                || libc::chdir(cwd.as_ptr()) < 0
            {
                return Err(io::Error::last_os_error());
            }
            if kernel_control
                && (libc::fcntl(3, libc::F_SETFD, 0) < 0 || libc::fcntl(4, libc::F_SETFD, 0) < 0)
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    Ok((command, procs))
}

fn release_inherited_stdio() -> io::Result<()> {
    let null = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/null")?;
    // Keep the source away from 0/1/2, even if one was already closed. A live
    // supervisor must never keep a workload pipe readable/writable by itself.
    let source = duplicate(null.as_raw_fd())?;
    drop(null);
    for descriptor in [0, 1, 2] {
        if unsafe { libc::dup2(source.as_raw_fd(), descriptor) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

fn supervise(control: &mut UnixStream, dir: &File) -> io::Result<()> {
    check_group(dir)?;
    control.set_read_timeout(Some(Duration::from_secs(2)))?;
    control.set_write_timeout(Some(Duration::from_millis(250)))?;
    let configuration = receive_spec(control)?;
    control.set_read_timeout(None)?;
    control.set_nonblocking(true)?;
    match action(control)? {
        Action::Stop => {
            send(control, &Event::CancelledBeforeStart)?;
            send(control, &Event::Complete { status: 130 << 8 })?;
            return Ok(());
        }
        Action::Interrupt => return Err(invalid("interrupt before workload startup")),
        Action::None => (),
    }
    if unsafe { libc::prctl(libc::PR_SET_CHILD_SUBREAPER, 1) } < 0 {
        return Err(io::Error::last_os_error());
    }
    let kernel_io = if configuration.kernel_control {
        Some(reserve_kernel_io()?)
    } else {
        None
    };
    let (mut command, membership) =
        child_command(configuration.spec, dir, configuration.kernel_control)?;
    let child = command.spawn();
    drop(membership);
    // Spawn has completed the exec-error handshake. Only the interpreter now
    // owns its fd3/fd4 endpoints; retain neither direction in the supervisor.
    drop(kernel_io);
    let child = match child {
        Ok(child) => child,
        Err(error) => {
            kill_group(dir)?;
            send(
                control,
                &Event::SpawnFailed {
                    message: error.to_string().chars().take(512).collect(),
                },
            )?;
            send(control, &Event::Complete { status: 127 << 8 })?;
            return Ok(());
        }
    };
    release_inherited_stdio()?;
    let main_pid = child.id() as i32;
    let main_pidfd = pidfd(child.id())?;
    drop(child); // Only this subreaper's waitpid loop owns process statuses.
    send(
        control,
        &Event::Started {
            pid: main_pid as u32,
        },
    )?;
    let mut main_status = None;
    let mut cleanup_deadline = None;
    loop {
        let mut no_children = false;
        for _ in 0..128 {
            let mut status = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid == main_pid {
                main_status = Some(status);
                send(control, &Event::Exited { status })?;
            }
            if pid == 0 {
                break;
            }
            if pid < 0 {
                if io::Error::last_os_error().raw_os_error() == Some(libc::ECHILD) {
                    no_children = true;
                    break;
                }
                return Err(io::Error::last_os_error());
            }
        }
        if cleanup_deadline.is_none() {
            let requested = if main_status.is_some() {
                Action::Stop
            } else {
                action(control)?
            };
            match requested {
                Action::Stop => {
                    kill_group(dir)?;
                    cleanup_deadline = Some(Instant::now() + CLEANUP);
                }
                Action::Interrupt => signal_pidfd(&main_pidfd, libc::SIGINT)?,
                Action::None => (),
            }
        }
        if no_children {
            if !empty_group(dir)? {
                return Err(invalid("subreaper empty but cgroup still populated"));
            }
            let status = main_status.ok_or_else(|| invalid("main workload status missing"))?;
            send(control, &Event::Complete { status })?;
            return Ok(());
        }
        if cleanup_deadline.is_some_and(|deadline| Instant::now() >= deadline) {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "owned descendant cleanup deadline",
            ));
        }
        let mut poll = libc::pollfd {
            fd: control.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        unsafe {
            libc::poll(&mut poll, 1, 5);
        }
    }
}

/// Check this before the normal agent PID1 guard. Returns None for normal boot.
pub fn dispatch_helper() -> Option<i32> {
    let arguments: Vec<_> = std::env::args_os().collect();
    if arguments
        .get(1)
        .is_none_or(|s| s != "--workload-supervisor")
    {
        return None;
    }
    if arguments.len() != 2 || unsafe { libc::geteuid() } != 0 || unsafe { libc::getppid() } != 1 {
        return Some(2);
    }
    unsafe {
        if libc::fcntl(CONTROL, libc::F_GETFD) < 0 || libc::fcntl(GROUP, libc::F_GETFD) < 0 {
            return Some(2);
        }
        libc::fcntl(CONTROL, libc::F_SETFD, libc::FD_CLOEXEC);
        libc::fcntl(GROUP, libc::F_SETFD, libc::FD_CLOEXEC);
        // Optional language transport never leaks in an ordinary command.
        libc::fcntl(KERNEL_INPUT, libc::F_SETFD, libc::FD_CLOEXEC);
        libc::fcntl(KERNEL_OUTPUT, libc::F_SETFD, libc::FD_CLOEXEC);
    }
    let mut control = unsafe { UnixStream::from_raw_fd(CONTROL) };
    let group = unsafe { File::from_raw_fd(GROUP) };
    match supervise(&mut control, &group) {
        Ok(()) => Some(0),
        Err(_) => {
            let _ = kill_group(&group);
            let _ = send(
                &mut control,
                &Event::Failed {
                    message: "workload supervision failed".into(),
                },
            );
            Some(2)
        }
    }
}
