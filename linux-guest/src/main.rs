use serde::{Deserialize, Serialize};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

const PROTOCOL: &str = "fc-agent/v1";
const RESULT_PREFIX: &str = "FC_AGENT_RESULT ";
const VSOCK_PORT: u32 = 5000;
const SANDBOX_UID: libc::uid_t = 10_000;
const SANDBOX_GID: libc::gid_t = 10_000;

#[cfg(target_env = "musl")]
type RlimitResource = libc::c_int;
#[cfg(not(target_env = "musl"))]
type RlimitResource = libc::c_uint;

#[derive(Deserialize)]
struct JobRequest {
    protocol: String,
    job_id: String,
    argv: Vec<String>,
    timeout_ms: u64,
    max_output_bytes: usize,
}

#[derive(Serialize)]
struct JobResult {
    protocol: &'static str,
    job_id: String,
    ok: bool,
    exit_code: i32,
    timed_out: bool,
    duration_ms: u128,
    stdout: String,
    stderr: String,
    output_truncated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Default)]
struct CapturedOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    total: usize,
    limit: usize,
    truncated: bool,
}

fn main() {
    redirect_stdio_to_console();
    println!("firecracker-linux-agent: init");
    let init_error = initialize_guest().err().map(|error| error.to_string());
    let vsock_port = configured_vsock_port();
    let listener = match listen_vsock(vsock_port) {
        Ok(listener) => listener,
        Err(error) => fatal(&format!("listen on vsock: {error}")),
    };
    println!("firecracker-linux-agent: ready port={vsock_port}");
    let connection = match accept_vsock(listener) {
        Ok(connection) => connection,
        Err(error) => fatal(&format!("accept vsock: {error}")),
    };
    unsafe { libc::close(listener) };

    let reader_file = connection.try_clone().unwrap_or_else(|error| fatal(&error.to_string()));
    let mut reader = BufReader::new(reader_file);
    let mut request_line = String::new();
    if let Err(error) = reader.read_line(&mut request_line) {
        fatal(&format!("read request: {error}"));
    }
    let request: JobRequest = match serde_json::from_str(&request_line) {
        Ok(request) => request,
        Err(error) => {
            write_error(connection, "unknown", &format!("invalid request JSON: {error}"));
            poweroff();
        }
    };

    let result = if let Some(error) = init_error {
        error_result(&request.job_id, format!("guest initialization failed: {error}"))
    } else if let Err(error) = validate_request(&request) {
        error_result(&request.job_id, error)
    } else {
        run_job(request)
    };
    let mut writer = connection;
    let encoded = serde_json::to_string(&result).unwrap_or_else(|_| {
        format!(
            "{{\"protocol\":\"{PROTOCOL}\",\"job_id\":\"unknown\",\"ok\":false,\"exit_code\":-1,\"timed_out\":false,\"duration_ms\":0,\"stdout\":\"\",\"stderr\":\"\",\"output_truncated\":false,\"error\":\"encode result failed\"}}"
        )
    });
    let _ = writeln!(writer, "{RESULT_PREFIX}{encoded}");
    let _ = writer.flush();
    unsafe { libc::sync() };
    poweroff();
}

fn validate_request(request: &JobRequest) -> Result<(), String> {
    if request.protocol != PROTOCOL {
        return Err("unsupported protocol".into());
    }
    if request.job_id.len() != 24
        || !request.job_id.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err("invalid job id".into());
    }
    if request.argv.is_empty() || request.argv.len() > 65 {
        return Err("argv must contain between 1 and 65 elements".into());
    }
    if request.argv.iter().any(|value| value.len() > 4096 || value.contains('\0')) {
        return Err("invalid argv element".into());
    }
    if request.timeout_ms == 0 || request.timeout_ms > 300_000 {
        return Err("timeout is outside the guest policy".into());
    }
    if request.max_output_bytes < 1024 || request.max_output_bytes > 4 * 1024 * 1024 {
        return Err("output limit is outside the guest policy".into());
    }
    Ok(())
}

fn configured_vsock_port() -> u32 {
    fs::read_to_string("/proc/cmdline")
        .ok()
        .and_then(|cmdline| {
            cmdline.split_whitespace().find_map(|value| {
                value
                    .strip_prefix("agent.vsock_port=")
                    .and_then(|port| port.parse::<u32>().ok())
                    .filter(|port| *port >= 1024)
            })
        })
        .unwrap_or(VSOCK_PORT)
}

fn run_job(request: JobRequest) -> JobResult {
    let started = Instant::now();
    let output = Arc::new(Mutex::new(CapturedOutput {
        limit: request.max_output_bytes,
        ..CapturedOutput::default()
    }));
    let mut command = Command::new(&request.argv[0]);
    command
        .args(&request.argv[1..])
        .current_dir("/workspace")
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", "/workspace")
        .env("LANG", "C.UTF-8")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    unsafe {
        command.pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            set_limit(libc::RLIMIT_CORE as RlimitResource, 0)?;
            set_limit(libc::RLIMIT_NOFILE as RlimitResource, 128)?;
            set_limit(libc::RLIMIT_NPROC as RlimitResource, 64)?;
            set_limit(libc::RLIMIT_FSIZE as RlimitResource, 64 * 1024 * 1024)?;
            if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0
                || libc::setgid(SANDBOX_GID) < 0
                || libc::setuid(SANDBOX_UID) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            return error_result(
                &request.job_id,
                format!("spawn {}: {error}", request.argv[0]),
            );
        }
    };
    let stdout_thread = child
        .stdout
        .take()
        .map(|pipe| capture_pipe(pipe, Arc::clone(&output), true));
    let stderr_thread = child
        .stderr
        .take()
        .map(|pipe| capture_pipe(pipe, Arc::clone(&output), false));
    let deadline = started + Duration::from_millis(request.timeout_ms);
    let (status, timed_out) = loop {
        match child.try_wait() {
            Ok(Some(status)) => break (Some(status), false),
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(2)),
            Ok(None) => {
                unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
                break (child.wait().ok(), true);
            }
            Err(_) => break (None, false),
        }
    };
    if let Some(handle) = stdout_thread {
        let _ = handle.join();
    }
    if let Some(handle) = stderr_thread {
        let _ = handle.join();
    }
    let captured = output.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    let exit_code = status
        .as_ref()
        .and_then(|status| status.code().or_else(|| status.signal().map(|signal| 128 + signal)))
        .unwrap_or(-1);
    JobResult {
        protocol: PROTOCOL,
        job_id: request.job_id,
        ok: !timed_out && status.is_some_and(|value| value.success()),
        exit_code,
        timed_out,
        duration_ms: started.elapsed().as_millis(),
        stdout: String::from_utf8_lossy(&captured.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&captured.stderr).into_owned(),
        output_truncated: captured.truncated,
        error: timed_out.then(|| "guest command timed out".into()),
    }
}

fn capture_pipe<R: Read + Send + 'static>(
    mut pipe: R,
    output: Arc<Mutex<CapturedOutput>>,
    stdout: bool,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0_u8; 4096];
        while let Ok(count) = pipe.read(&mut buffer) {
            if count == 0 {
                break;
            }
            let mut captured = output.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
            let remaining = captured.limit.saturating_sub(captured.total);
            let keep = remaining.min(count);
            if stdout {
                captured.stdout.extend_from_slice(&buffer[..keep]);
            } else {
                captured.stderr.extend_from_slice(&buffer[..keep]);
            }
            captured.total += keep;
            if keep < count {
                captured.truncated = true;
            }
        }
    })
}

fn initialize_guest() -> Result<(), Box<dyn std::error::Error>> {
    fs::create_dir_all("/proc")?;
    fs::create_dir_all("/sys")?;
    fs::create_dir_all("/dev")?;
    fs::create_dir_all("/run")?;
    fs::create_dir_all("/tmp")?;
    fs::create_dir_all("/workspace")?;
    fs::create_dir_all("/input")?;
    mount_optional("proc", "/proc", "proc", 0, None);
    mount_optional("sysfs", "/sys", "sysfs", 0, None);
    mount_optional("devtmpfs", "/dev", "devtmpfs", 0, Some("mode=0755"));
    mount_optional("tmpfs", "/run", "tmpfs", libc::MS_NOSUID, Some("size=16m"));
    mount_optional(
        "tmpfs",
        "/tmp",
        "tmpfs",
        libc::MS_NOSUID | libc::MS_NODEV,
        Some("size=64m,mode=1777"),
    );
    mount_required(
        "/dev/vdb",
        "/workspace",
        "ext4",
        libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOATIME,
        None,
    )?;
    if std::path::Path::new("/dev/vdc").exists() {
        mount_required(
            "/dev/vdc",
            "/input",
            "ext4",
            libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC | libc::MS_NOATIME,
            None,
        )?;
    }
    let workspace = CString::new("/workspace")?;
    if unsafe { libc::chown(workspace.as_ptr(), SANDBOX_UID, SANDBOX_GID) } < 0
        || unsafe { libc::chmod(workspace.as_ptr(), 0o700) } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}

fn mount_optional(source: &str, target: &str, fs_type: &str, flags: libc::c_ulong, data: Option<&str>) {
    if let Err(error) = mount(source, target, fs_type, flags, data) {
        // devtmpfs can already be mounted by the kernel before PID 1 starts.
        if error.raw_os_error() != Some(libc::EBUSY) {
            eprintln!("optional mount {target} failed: {error}");
        }
    }
}

fn mount_required(
    source: &str,
    target: &str,
    fs_type: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<(), std::io::Error> {
    mount(source, target, fs_type, flags, data)
}

fn mount(source: &str, target: &str, fs_type: &str, flags: libc::c_ulong, data: Option<&str>) -> Result<(), std::io::Error> {
    let source = CString::new(source).unwrap();
    let target = CString::new(target).unwrap();
    let fs_type = CString::new(fs_type).unwrap();
    let data = data.map(|value| CString::new(value).unwrap());
    let data_ptr = data
        .as_ref()
        .map_or(std::ptr::null(), |value| value.as_ptr().cast());
    let result = unsafe {
        libc::mount(
            source.as_ptr(), target.as_ptr(), fs_type.as_ptr(), flags, data_ptr,
        )
    };
    if result < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

unsafe fn set_limit(resource: RlimitResource, value: libc::rlim_t) -> Result<(), std::io::Error> {
    let limit = libc::rlimit { rlim_cur: value, rlim_max: value };
    if unsafe { libc::setrlimit(resource, &limit) } < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

#[repr(C)]
struct SockAddrVm {
    family: libc::sa_family_t,
    reserved: libc::c_ushort,
    port: u32,
    cid: u32,
    zero: [u8; 4],
}

fn listen_vsock(port: u32) -> Result<RawFd, std::io::Error> {
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let address = SockAddrVm {
        family: libc::AF_VSOCK as libc::sa_family_t,
        reserved: 0,
        port,
        cid: u32::MAX,
        zero: [0; 4],
    };
    let result = unsafe {
        libc::bind(
            fd,
            (&address as *const SockAddrVm).cast(),
            std::mem::size_of::<SockAddrVm>() as libc::socklen_t,
        )
    };
    if result < 0 || unsafe { libc::listen(fd, 1) } < 0 {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(error);
    }
    Ok(fd)
}

fn accept_vsock(listener: RawFd) -> Result<File, std::io::Error> {
    let fd = unsafe {
        libc::accept4(
            listener,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(unsafe { File::from_raw_fd(fd) })
    }
}

fn redirect_stdio_to_console() {
    let console = CString::new("/dev/console").unwrap();
    let fd = unsafe { libc::open(console.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC) };
    if fd >= 0 {
        unsafe {
            libc::dup2(fd, libc::STDIN_FILENO);
            libc::dup2(fd, libc::STDOUT_FILENO);
            libc::dup2(fd, libc::STDERR_FILENO);
            if fd > libc::STDERR_FILENO {
                libc::close(fd);
            }
        }
    }
}

fn write_error(mut connection: File, job_id: &str, message: &str) {
    let result = error_result(job_id, message.into());
    if let Ok(encoded) = serde_json::to_string(&result) {
        let _ = writeln!(connection, "{RESULT_PREFIX}{encoded}");
        let _ = connection.flush();
    }
}

fn error_result(job_id: &str, error: String) -> JobResult {
    JobResult {
        protocol: PROTOCOL,
        job_id: job_id.into(),
        ok: false,
        exit_code: -1,
        timed_out: false,
        duration_ms: 0,
        stdout: String::new(),
        stderr: String::new(),
        output_truncated: false,
        error: Some(error),
    }
}

fn fatal(message: &str) -> ! {
    eprintln!("firecracker-linux-agent: fatal: {message}");
    poweroff();
}

fn poweroff() -> ! {
    unsafe {
        // Firecracker's recommended x86 boot arguments use reboot=k. A Linux
        // power-off request can degrade to a halted vCPU when no ACPI poweroff
        // method is present, whereas RB_AUTOBOOT reaches the emulated keyboard
        // controller reset path and terminates the one-shot microVM.
        libc::reboot(libc::RB_AUTOBOOT);
    }
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_protocol_and_job_id() {
        let request = JobRequest {
            protocol: PROTOCOL.into(),
            job_id: "0123456789abcdef01234567".into(),
            argv: vec!["/bin/true".into()],
            timeout_ms: 1000,
            max_output_bytes: 4096,
        };
        assert!(validate_request(&request).is_ok());
    }

    #[test]
    fn rejects_unbounded_output() {
        let request = JobRequest {
            protocol: PROTOCOL.into(),
            job_id: "0123456789abcdef01234567".into(),
            argv: vec!["/bin/true".into()],
            timeout_ms: 1000,
            max_output_bytes: usize::MAX,
        };
        assert!(validate_request(&request).is_err());
    }
}
