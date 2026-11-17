use base64::{Engine, engine::general_purpose::STANDARD};
use firecracker_linux_agent::{code_service, port_service, workload};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::os::unix::fs::MetadataExt;
#[cfg(test)]
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::path::Path;
#[cfg(test)]
use std::process::{Child, Stdio};
use std::process::{ChildStderr, ChildStdin, ChildStdout, Command, ExitStatus};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(test)]
mod code_vm_tests;
#[cfg(test)]
mod port_vm_tests;
#[cfg(test)]
mod vsock_accept_tests;
mod command_stdin;
mod artifacts;
mod file_watch;
mod job_stdin;
mod network_proxy;
mod pristine;
mod streaming;
#[cfg(test)]
mod workload_vm_tests;
mod workspace_mutations;

const PROTOCOL: &str = "fc-agent/v1";
const SESSION_PROTOCOL: &str = "fc-agent/v2";
const RESULT_PREFIX: &str = "FC_AGENT_RESULT ";
const VSOCK_PORT: u32 = 5000;
const SESSION_MAX_AGE: Duration = Duration::from_secs(600);
const SESSION_MAX_REQUESTS: usize = 100;
const REQUEST_LIMIT: u64 = 1 << 20;
const FILE_LIMIT: usize = 512 * 1024;
const FILE_LIST_LIMIT: usize = 256;
const FILE_LIST_NAME_BYTES_LIMIT: usize = 64 * 1024;
const SANDBOX_UID: libc::uid_t = 10_000;
const SANDBOX_GID: libc::gid_t = 10_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JobRequest {
    protocol: String,
    job_id: String,
    #[serde(default)]
    operation: Option<String>,
    #[serde(default)]
    argv: Vec<String>,
    #[serde(default)]
    timeout_ms: u64,
    #[serde(default)]
    max_output_bytes: usize,
    #[serde(default)]
    file: Option<FileRequest>,
    #[serde(default)]
    binding: Option<pristine::Binding>,
    #[serde(default)]
    prepare: Option<pristine::PrepareRequest>,
    #[serde(default)]
    environment: BTreeMap<String, String>,
    #[serde(default)]
    cwd: Option<String>,
    #[serde(default)]
    interactive_stdin: bool,
    #[serde(default)]
    stdin: Option<String>,
}

#[derive(Deserialize)]
struct FileRequest {
    action: String,
    path: String,
    #[serde(default)]
    destination: Option<String>,
    #[serde(default)]
    data_base64: Option<String>,
    #[serde(default)]
    metadata: Option<BTreeMap<String, String>>,
}

#[derive(Serialize)]
struct FileResult {
    action: String,
    path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    destination: Option<String>,
    size: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    data_base64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    kind: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entries: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    created: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    info: Option<FileInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    entry_infos: Option<Vec<FileInfo>>,
}

#[derive(Serialize)]
struct FileInfo {
    name: String,
    path: String,
    #[serde(rename = "type")]
    file_type: &'static str,
    size: u64,
    mode: u32,
    permissions: String,
    owner: String,
    group: String,
    modified_time_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    symlink_target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    metadata: Option<BTreeMap<String, String>>,
}

#[derive(Serialize)]
struct JobResult {
    proxy_revision: u32,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    file_result: Option<FileResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    file_error_code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding: Option<pristine::Binding>,
    #[serde(skip_serializing_if = "Option::is_none")]
    guest_state: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    remaining_lifetime_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pristine_revision: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code_service: Option<code_service::Readiness>,
    #[serde(skip_serializing_if = "Option::is_none")]
    port_service: Option<port_service::Readiness>,
}

#[derive(Default)]
struct CapturedOutput {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    total: usize,
    limit: usize,
    truncated: bool,
    stream: Option<streaming::StreamWriter>,
}

fn main() {
    osv_runtime_allocator::initialize();
    if let Some(status) = workload::dispatch_helper() {
        std::process::exit(status);
    }
    if unsafe { libc::getpid() } != 1 {
        eprintln!("agent-init must run as guest PID 1");
        std::process::exit(2);
    }
    workload::install_failure_handler(poweroff)
        .unwrap_or_else(|error| fatal(&format!("workload failure handler: {error}")));
    redirect_stdio_to_console();
    println!("firecracker-linux-agent: init");
    fs::create_dir_all("/proc").unwrap_or_else(|error| fatal(&format!("create proc: {error}")));
    mount_optional("proc", "/proc", "proc", 0, None);
    let pristine_mode = fs::read_to_string("/proc/cmdline")
        .unwrap_or_else(|error| fatal(&format!("read boot policy: {error}")))
        .split_whitespace()
        .any(|arg| arg == "agent.pristine=1");
    let init_error = initialize_guest(pristine_mode)
        .and_then(|()| {
            let enabled = fs::read_to_string("/proc/cmdline")?
                .split_whitespace()
                .any(|arg| arg == "agent.proxy=5001");
            if enabled {
                if pristine_mode {
                    return Err("pristine boot cannot contain network permission".into());
                }
                network_proxy::enable()?;
            }
            Ok(())
        })
        .err()
        .map(|error| error.to_string());
    let vsock_port = configured_vsock_port();
    let listener = match listen_vsock(vsock_port) {
        Ok(listener) => listener,
        Err(error) => fatal(&format!("listen on vsock: {error}")),
    };
    let started = Instant::now();
    let mut runtime = if pristine_mode {
        pristine::Runtime::Pristine
    } else {
        pristine::Runtime::Legacy
    };
    let mut budget = pristine::RequestBudget::default();
    let watch_enabled = fs::read_to_string("/proc/cmdline").is_ok_and(|line| {
        line.split_whitespace()
            .any(|part| part == "agent.watch=5002")
    });
    let watch_service = if watch_enabled && init_error.is_none() {
        Some(
            file_watch::Service::start(
                Path::new("/workspace"),
                &runtime,
                started + SESSION_MAX_AGE,
            )
            .unwrap_or_else(|error| fatal(&format!("start workspace watch: {error}"))),
        )
    } else {
        None
    };
    let code_service = start_code_service(
        &fs::read_to_string("/proc/cmdline")
            .unwrap_or_else(|error| fatal(&format!("read code boot policy: {error}"))),
        init_error.as_deref(),
        started + SESSION_MAX_AGE,
    )
    .unwrap_or_else(|error| fatal(&format!("start code service: {error}")));
    let ports = start_port_service(
        &fs::read_to_string("/proc/cmdline")
            .unwrap_or_else(|error| fatal(&format!("read port boot policy: {error}"))),
        init_error.as_deref(),
        started + SESSION_MAX_AGE,
    ).unwrap_or_else(|error| fatal(&format!("start port service: {error}")));
    let artifacts = start_artifact_service(
        &fs::read_to_string("/proc/cmdline")
            .unwrap_or_else(|error| fatal(&format!("read artifact boot policy: {error}"))),
        init_error.as_deref(), &runtime, started + SESSION_MAX_AGE,
    ).unwrap_or_else(|error| fatal(&format!("start artifact service: {error}")));
    println!("firecracker-linux-agent: ready port={vsock_port}");
    while budget.permits() {
        let Some(connection) =
            accept_host_vsock_until(listener, runtime.accept_deadline(started + SESSION_MAX_AGE))
                .unwrap_or_else(|error| fatal(&format!("accept host vsock: {error}")))
        else {
            break;
        };
        let was_pristine = runtime.is_pristine();
        if handle_connection_artifacts(
            connection,
            init_error.as_deref(),
            started + SESSION_MAX_AGE,
            &mut runtime,
            ConnectionServices {
                watch: watch_service.as_ref(),
                code: code_service.as_ref(),
                ports: ports.as_ref(),
                artifacts: artifacts.as_ref(),
            },
        ) == ConnectionAction::Poweroff
        {
            break;
        }
        budget.record(was_pristine, &runtime);
        if let Some(service) = &watch_service {
            service.update(&runtime, started + SESSION_MAX_AGE);
        }
    }
    drop(artifacts);
    drop(ports);
    drop(code_service);
    drop(watch_service);
    unsafe { libc::close(listener) };
    unsafe { libc::sync() };
    poweroff();
}

#[derive(Debug, PartialEq, Eq)]
enum ConnectionAction {
    Continue,
    Poweroff,
}

#[cfg(test)]
fn handle_connection(
    connection: File,
    init_error: Option<&str>,
    deadline: Instant,
) -> ConnectionAction {
    handle_connection_state(
        connection,
        init_error,
        deadline,
        &mut pristine::Runtime::Legacy,
    )
}

#[cfg(test)]
fn handle_connection_state(
    connection: File,
    init_error: Option<&str>,
    session_deadline: Instant,
    runtime: &mut pristine::Runtime,
) -> ConnectionAction {
    handle_connection_watch(connection, init_error, session_deadline, runtime, None)
}

#[cfg(test)]
fn handle_connection_watch(
    connection: File,
    init_error: Option<&str>,
    session_deadline: Instant,
    runtime: &mut pristine::Runtime,
    watch: Option<&file_watch::Service>,
) -> ConnectionAction {
    handle_connection_services(
        connection,
        init_error,
        session_deadline,
        runtime,
        watch,
        None,
    )
}

#[cfg(test)]
fn handle_connection_services(
    connection: File,
    init_error: Option<&str>,
    session_deadline: Instant,
    runtime: &mut pristine::Runtime,
    watch: Option<&file_watch::Service>,
    code: Option<&code_service::Service>,
) -> ConnectionAction {
    handle_connection_all(connection, init_error, session_deadline, runtime, watch, code, None)
}

#[cfg(test)]
fn handle_connection_all(
    connection: File,
    init_error: Option<&str>,
    session_deadline: Instant,
    runtime: &mut pristine::Runtime,
    watch: Option<&file_watch::Service>,
    code: Option<&code_service::Service>,
    ports: Option<&port_service::Service>,
) -> ConnectionAction {
    handle_connection_artifacts(connection, init_error, session_deadline, runtime, ConnectionServices {
        watch, code, ports, artifacts: None,
    })
}

#[derive(Default)]
struct ConnectionServices<'a> {
    watch: Option<&'a file_watch::Service>,
    code: Option<&'a code_service::Service>,
    ports: Option<&'a port_service::Service>,
    artifacts: Option<&'a artifacts::Service>,
}

fn handle_connection_artifacts(
    mut connection: File,
    init_error: Option<&str>,
    session_deadline: Instant,
    runtime: &mut pristine::Runtime,
    services: ConnectionServices<'_>,
) -> ConnectionAction {
    let ConnectionServices { watch, code, ports, artifacts } = services;
    let reader_file = match connection.try_clone() {
        Ok(file) => file,
        Err(_) => return ConnectionAction::Continue,
    };
    let mut reader = BufReader::new(reader_file);
    let mut request_line = Vec::new();
    let read = reader
        .by_ref()
        .take(REQUEST_LIMIT)
        .read_until(b'\n', &mut request_line);
    if !matches!(read, Ok(count) if count > 0 && request_line.last() == Some(&b'\n')) {
        let action = runtime.invalid_frame();
        if action == ConnectionAction::Poweroff { revoke_services(code, ports, artifacts); }
        write_result(
            &mut connection,
            &error_result(
                "unknown",
                if runtime.enabled() {
                    pristine::PROTOCOL
                } else {
                    PROTOCOL
                },
                "invalid request frame".into(),
            ),
        );
        return action;
    }
    let mut request: JobRequest = match serde_json::from_slice(&request_line) {
        Ok(request) => request,
        Err(error) => {
            let action = runtime.invalid_frame();
            if action == ConnectionAction::Poweroff { revoke_services(code, ports, artifacts); }
            write_result(
                &mut connection,
                &error_result(
                    "unknown",
                    if runtime.enabled() {
                        pristine::PROTOCOL
                    } else {
                        PROTOCOL
                    },
                    format!("invalid request JSON: {error}"),
                ),
            );
            return action;
        }
    };
    let stream = if request.operation.as_deref() == Some("run_stream") {
        match connection
            .try_clone()
            .and_then(|file| streaming::StreamWriter::new(file, &request, reader.buffer().to_vec()))
        {
            Ok(stream) => Some(stream),
            Err(error) => {
                revoke_services(code, ports, artifacts);
                write_result(
                    &mut connection,
                    &error_result(
                        &request.job_id,
                        result_protocol(&request.protocol),
                        format!("initialize stream: {error}"),
                    ),
                );
                return ConnectionAction::Poweroff;
            }
        }
    } else {
        None
    };
    if runtime.enabled() {
        let (mut result, action) = runtime.dispatch_stream(
            request,
            init_error,
            session_deadline,
            Path::new("/input"),
            Path::new("/workspace"),
            pristine::freeze_input,
            stream,
        );
        // Publish the prepared authorization before its ACK can reach the
        // host and trigger an independent watch request.
        if let Some(service) = watch {
            service.update(runtime, session_deadline);
        }
        synchronize_code(code, runtime, session_deadline);
        synchronize_ports(ports, runtime, session_deadline);
        if let Some(service) = artifacts { service.update(runtime, session_deadline); }
        if result.ok {
            result.code_service = code.and_then(code_service::Service::readiness);
            result.port_service = ports.and_then(port_service::Service::readiness);
        }
        write_result(&mut connection, &result);
        return action;
    }
    let protocol = result_protocol(&request.protocol);
    let valid = if request.protocol == pristine::PROTOCOL {
        Err("pristine protocol requires a pristine boot".into())
    } else {
        validate_request(&request)
    };
    let action = if request.protocol == PROTOCOL
        || (valid.is_ok() && request.operation.as_deref() == Some("shutdown"))
        || Instant::now() >= session_deadline
    {
        ConnectionAction::Poweroff
    } else {
        ConnectionAction::Continue
    };
    if valid.is_ok()
        && init_error.is_none()
        && request.protocol == SESSION_PROTOCOL
        && Instant::now() < session_deadline
    {
        if let Some(service) = watch {
            service.authorize_legacy_session(session_deadline);
        }
        if action == ConnectionAction::Continue
            && let Some(service) = code
        {
            service
                .authorize_legacy(session_deadline)
                .unwrap_or_else(|error| fatal(&format!("authorize code session: {error}")));
        }
        if action == ConnectionAction::Continue && request.operation.as_deref() == Some("ping")
            && let Some(service) = ports
        {
            service.authorize_legacy(session_deadline)
                .unwrap_or_else(|error| fatal(&format!("authorize port session: {error}")));
        }
        if action == ConnectionAction::Continue && let Some(service) = artifacts {
            service.authorize_legacy_session(session_deadline);
        }
    }
    if action == ConnectionAction::Poweroff { revoke_services(code, ports, artifacts); }
    let mut result = if let Some(error) = init_error {
        error_result(
            &request.job_id,
            protocol,
            format!("guest initialization failed: {error}"),
        )
    } else if let Err(error) = valid {
        error_result(&request.job_id, protocol, error)
    } else if request.protocol == SESSION_PROTOCOL && Instant::now() >= session_deadline {
        error_result(&request.job_id, protocol, "session lifetime expired".into())
    } else if request.operation.as_deref() == Some("ping")
        || request.operation.as_deref() == Some("shutdown")
    {
        success_result(&request.job_id, protocol)
    } else if request.operation.as_deref() == Some("file") {
        run_file(&request, Path::new("/workspace"))
    } else {
        if request.protocol == SESSION_PROTOCOL {
            let remaining_ms = session_deadline
                .saturating_duration_since(Instant::now())
                .as_millis()
                .max(1) as u64;
            request.timeout_ms = request.timeout_ms.min(remaining_ms);
        }
        if request.operation.as_deref() == Some("run_stream") {
            run_job_stream(request, stream)
        } else {
            run_job(request)
        }
    };
    if result.ok {
        result.code_service = code.and_then(code_service::Service::readiness);
        result.port_service = ports.and_then(port_service::Service::readiness);
    }
    write_result(&mut connection, &result);
    action
}

fn code_prewarm_policy(
    line: &str,
) -> Result<Option<firecracker_linux_agent::code_context::Language>, &'static str> {
    use firecracker_linux_agent::code_context::Language;
    let enabled: Vec<_> = line
        .split_whitespace()
        .filter(|part| part.starts_with("agent.code="))
        .collect();
    let languages: Vec<_> = line
        .split_whitespace()
        .filter_map(|part| part.strip_prefix("agent.code-prewarm="))
        .collect();
    if enabled.is_empty() && languages.is_empty() {
        return Ok(None);
    }
    if enabled != ["agent.code=5003"] || languages.len() > 1 {
        return Err("invalid code boot policy");
    }
    let language = match languages.first().copied().unwrap_or("python") {
        "python" => Language::Python,
        "javascript" => Language::Javascript,
        "typescript" => Language::Typescript,
        _ => return Err("unsupported code prewarm language"),
    };
    Ok(Some(language))
}
fn port_policy(line: &str) -> Result<bool, &'static str> {
    let values: Vec<_> = line.split_whitespace().filter_map(|word| word.strip_prefix("agent.port=")).collect();
    match values.as_slice() {
        [] => Ok(false),
        ["5004"] => Ok(true),
        _ => Err("invalid port relay boot policy"),
    }
}

fn start_port_service(line: &str, init_error: Option<&str>, hard: Instant) -> io::Result<Option<port_service::Service>> {
    if !port_policy(line).map_err(io::Error::other)? { return Ok(None); }
    if init_error.is_some() { return Err(io::Error::other("port template initialization failed")); }
    network_proxy::enable_loopback()?;
    let listener = unsafe { File::from_raw_fd(listen_vsock(port_service::PORT)?) };
    port_service::Service::start(listener, accept_host_vsock_until, port_service::Options::packaged(hard)).map(Some)
}

fn revoke_services(code: Option<&code_service::Service>, ports: Option<&port_service::Service>, artifacts: Option<&artifacts::Service>) {
    if let Some(service) = artifacts { service.revoke(); }
    if let Some(service) = ports { service.revoke(); }
    if let Some(service) = code { service.revoke(); }
}

fn artifact_policy(line: &str) -> Result<bool, &'static str> {
    let values: Vec<_> = line.split_whitespace().filter_map(|word| word.strip_prefix("agent.artifacts=")).collect();
    match values.as_slice() {
        [] => Ok(false),
        ["5005"] => Ok(true),
        _ => Err("invalid workspace artifact boot policy"),
    }
}

fn start_artifact_service(line: &str, init_error: Option<&str>, runtime: &pristine::Runtime, hard: Instant) -> io::Result<Option<artifacts::Service>> {
    if !artifact_policy(line).map_err(io::Error::other)? { return Ok(None); }
    if init_error.is_some() { return Err(io::Error::other("artifact template initialization failed")); }
    artifacts::Service::start(Path::new("/workspace"), runtime, hard).map(Some)
}

fn synchronize_ports(service: Option<&port_service::Service>, runtime: &pristine::Runtime, hard: Instant) {
    let Some(service) = service else { return; };
    match runtime {
        pristine::Runtime::Legacy | pristine::Runtime::Pristine => (),
        pristine::Runtime::Prepared { binding, deadline, one_shot: false } => {
            service.authorize_prepared(port_service::Binding { session_id: binding.session_id.clone(), nonce: binding.nonce.clone() }, (*deadline).min(hard))
                .unwrap_or_else(|error| fatal(&format!("authorize prepared ports: {error}")));
        }
        _ => service.revoke(),
    }
}

fn start_code_service(
    line: &str,
    init_error: Option<&str>,
    hard: Instant,
) -> io::Result<Option<code_service::Service>> {
    let Some(language) = code_prewarm_policy(line).map_err(io::Error::other)? else {
        return Ok(None);
    };
    if init_error.is_some() {
        return Err(io::Error::other("code template initialization failed"));
    }
    let listener = unsafe { File::from_raw_fd(listen_vsock(code_service::PORT)?) };
    code_service::Service::start(
        listener,
        accept_host_vsock_until,
        firecracker_linux_agent::code_context::Options::packaged(hard),
        Some(language),
    )
    .map(Some)
}
fn synchronize_code(
    service: Option<&code_service::Service>,
    runtime: &pristine::Runtime,
    hard: Instant,
) {
    let Some(service) = service else {
        return;
    };
    match runtime {
        pristine::Runtime::Pristine | pristine::Runtime::Legacy => {}
        pristine::Runtime::Prepared {
            binding,
            deadline,
            one_shot: false,
        } => {
            service
                .authorize_prepared(binding.clone(), (*deadline).min(hard))
                .unwrap_or_else(|error| fatal(&format!("authorize prepared code: {error}")));
        }
        _ => service.revoke(),
    }
}

fn write_result(writer: &mut File, result: &JobResult) {
    if let Ok(encoded) = serde_json::to_string(result) {
        let _ = writeln!(writer, "{RESULT_PREFIX}{encoded}");
        let _ = writer.flush();
    }
}

fn result_protocol(protocol: &str) -> &'static str {
    if protocol == pristine::PROTOCOL {
        pristine::PROTOCOL
    } else if protocol == SESSION_PROTOCOL {
        SESSION_PROTOCOL
    } else {
        PROTOCOL
    }
}

fn success_result(job_id: &str, protocol: &'static str) -> JobResult {
    JobResult {
        proxy_revision: 1,
        protocol,
        job_id: job_id.into(),
        ok: true,
        exit_code: 0,
        timed_out: false,
        duration_ms: 0,
        stdout: String::new(),
        stderr: String::new(),
        output_truncated: false,
        error: None,
        file_result: None,
        file_error_code: None,
        binding: None,
        guest_state: None,
        remaining_lifetime_ms: None,
        pristine_revision: None,
        code_service: None,
        port_service: None,
    }
}

fn validate_request(request: &JobRequest) -> Result<(), String> {
    if request.protocol != PROTOCOL
        && request.protocol != SESSION_PROTOCOL
        && request.protocol != pristine::PROTOCOL
    {
        return Err("unsupported protocol".into());
    }
    if request.protocol != pristine::PROTOCOL
        && (request.binding.is_some() || request.prepare.is_some())
    {
        return Err("legacy protocol does not accept preparation or binding".into());
    }
    if request.job_id.len() != 24 || !request.job_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("invalid job id".into());
    }
    if request.protocol == PROTOCOL && (request.operation.is_some() || request.file.is_some()) {
        return Err("v1 does not accept an operation".into());
    }
    if request.interactive_stdin && request.operation.as_deref() != Some("run_stream") {
        return Err("interactive stdin requires run_stream".into());
    }
    if let Some(encoded) = request.stdin.as_deref() {
        if request.interactive_stdin || !matches!(request.operation.as_deref(), None | Some("run"))
        {
            return Err("fixed stdin requires a synchronous execution".into());
        }
        job_stdin::decode(encoded).map_err(|error| error.to_string())?;
    }
    if request.environment.len() > 32
        || request.environment.iter().any(|(name, value)| {
            name.is_empty()
                || name.len() > 64
                || value.len() > 1024
                || value.contains('\0')
                || !name.bytes().enumerate().all(|(i, b)| {
                    b == b'_' || b.is_ascii_alphabetic() || i > 0 && b.is_ascii_digit()
                })
        })
        || request
            .environment
            .iter()
            .map(|(k, v)| k.len() + v.len())
            .sum::<usize>()
            > 8192
    {
        return Err("invalid or oversized command environment".into());
    }
    if request.cwd.as_ref().is_some_and(|cwd| {
        !cwd.starts_with('/') || cwd.len() > 1024 || cwd.chars().any(char::is_control)
    }) {
        return Err("cwd must be a guest absolute path without control characters".into());
    }
    if !matches!(
        request.operation.as_deref(),
        Some("run" | "run_stream") | None
    ) && (!request.environment.is_empty() || request.cwd.is_some())
    {
        return Err("non-execution operation does not accept environment or cwd".into());
    }
    if request.protocol == SESSION_PROTOCOL || request.protocol == pristine::PROTOCOL {
        match request.operation.as_deref() {
            Some("ping" | "shutdown")
                if request.argv.is_empty()
                    && request.timeout_ms == 0
                    && request.max_output_bytes == 0
                    && request.file.is_none() =>
            {
                return Ok(());
            }
            Some("file")
                if request.argv.is_empty()
                    && request.timeout_ms == 0
                    && request.max_output_bytes == 0
                    && request.file.is_some() =>
            {
                return Ok(());
            }
            Some("run" | "run_stream") if request.file.is_none() => (),
            Some("prepare")
                if request.protocol == pristine::PROTOCOL
                    && request.prepare.is_some()
                    && request.binding.is_none()
                    && request.argv.is_empty()
                    && request.timeout_ms == 0
                    && request.max_output_bytes == 0
                    && request.file.is_none() =>
            {
                return Ok(());
            }
            _ => return Err("invalid session operation".into()),
        }
    }
    if request.argv.is_empty() || request.argv.len() > 65 {
        return Err("argv must contain between 1 and 65 elements".into());
    }
    if request
        .argv
        .iter()
        .any(|value| value.len() > 4096 || value.contains('\0'))
    {
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

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

// Linux openat2 constants are fixed UAPI values on both supported guests.
const RESOLVE_NO_XDEV: u64 = 0x01;
const RESOLVE_NO_SYMLINKS: u64 = 0x04;
const RESOLVE_BENEATH: u64 = 0x08;

fn clean_workspace_path(path: &str, allow_root: bool) -> Option<&str> {
    if allow_root && path == "/workspace" {
        return Some("");
    }
    let relative = path.strip_prefix("/workspace/")?;
    if relative.is_empty()
        || relative.len() > 1024
        || relative.contains('\\')
        || relative.chars().any(|ch| ch.is_control())
        || relative
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == ".." || part.len() > 255)
    {
        return None;
    }
    Some(relative)
}

fn open_beneath(root: RawFd, path: &str, flags: i32, mode: u32) -> io::Result<File> {
    let name = CString::new(path).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: mode as u64,
        resolve: RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_XDEV,
    };
    let fd = unsafe {
        libc::syscall(
            libc::SYS_openat2,
            root,
            name.as_ptr(),
            &how,
            std::mem::size_of::<OpenHow>(),
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd as RawFd) })
}

fn file_error_code(error: &io::Error) -> &'static str {
    match error.raw_os_error() {
        Some(libc::ENOENT) => "not_found",
        Some(libc::ELOOP | libc::EXDEV | libc::EACCES | libc::EPERM | libc::ENOTDIR) => "denied",
        Some(libc::EFBIG) => "too_large",
        Some(libc::E2BIG) => "operation_limit",
        Some(libc::EEXIST | libc::ENOTEMPTY | libc::EINVAL | libc::EISDIR) => "conflict",
        _ => "io_error",
    }
}

fn run_file(request: &JobRequest, workspace: &Path) -> JobResult {
    let Some(file) = request.file.as_ref() else {
        let mut result = error_result(
            &request.job_id,
            SESSION_PROTOCOL,
            "file request missing".into(),
        );
        result.file_error_code = Some("invalid_request");
        return result;
    };
    let allow_root = matches!(file.action.as_str(), "list" | "stat" | "info");
    let Some(relative) = clean_workspace_path(&file.path, allow_root) else {
        let mut result = error_result(
            &request.job_id,
            SESSION_PROTOCOL,
            "invalid workspace path".into(),
        );
        result.file_error_code = Some("invalid_path");
        return result;
    };
    if file.action != "write" && file.metadata.is_some() {
        let mut result = error_result(
            &request.job_id,
            SESSION_PROTOCOL,
            "file metadata is only valid for write".into(),
        );
        result.file_error_code = Some("invalid_request");
        return result;
    }
    if (file.action == "rename") != file.destination.is_some() {
        let mut result = error_result(
            &request.job_id,
            SESSION_PROTOCOL,
            "invalid rename destination".into(),
        );
        result.file_error_code = Some("invalid_request");
        return result;
    }
    let destination = match file.destination.as_deref() {
        Some(path) => match clean_workspace_path(path, false) {
            Some(relative) => Some(relative),
            None => {
                let mut result = error_result(
                    &request.job_id,
                    SESSION_PROTOCOL,
                    "invalid destination path".into(),
                );
                result.file_error_code = Some("invalid_path");
                return result;
            }
        },
        None => None,
    };
    if file.action == "mkdir" && relative.split('/').count() > 16 {
        let mut result = error_result(
            &request.job_id,
            SESSION_PROTOCOL,
            "directory depth exceeds 16".into(),
        );
        result.file_error_code = Some("invalid_path");
        return result;
    }
    let operation = match file.action.as_str() {
        "rename" if file.data_base64.is_none() => {
            workspace_mutations::rename(workspace, relative, destination.unwrap()).map(|info| {
                FileResult {
                    action: "rename".into(),
                    path: file.path.clone(),
                    destination: file.destination.clone(),
                    size: if info.file_type == "file" {
                        info.size as usize
                    } else {
                        0
                    },
                    kind: Some(info.file_type),
                    info: Some(info),
                    data_base64: None,
                    entries: None,
                    created: None,
                    entry_infos: None,
                }
            })
        }
        "remove" if file.data_base64.is_none() => workspace_mutations::remove(workspace, relative)
            .map(|()| FileResult {
                action: "remove".into(),
                path: file.path.clone(),
                destination: None,
                size: 0,
                kind: None,
                info: None,
                data_base64: None,
                entries: None,
                created: None,
                entry_infos: None,
            }),
        "read" if file.data_base64.is_none() => {
            read_workspace_file(workspace, relative).map(|bytes| FileResult {
                action: "read".into(),
                path: file.path.clone(),
                destination: None,
                size: bytes.len(),
                data_base64: Some(STANDARD.encode(bytes)),
                kind: None,
                entries: None,
                created: None,
                info: None,
                entry_infos: None,
            })
        }
        "write" => match file.data_base64.as_deref() {
            Some(encoded) if encoded.len() <= FILE_LIMIT.div_ceil(3) * 4 => {
                match STANDARD.decode(encoded) {
                    Ok(bytes) if bytes.len() <= FILE_LIMIT => write_workspace_file(
                        workspace,
                        relative,
                        &request.job_id,
                        &bytes,
                        file.metadata.as_ref(),
                    )
                    .map(|()| FileResult {
                        action: "write".into(),
                        path: file.path.clone(),
                        destination: None,
                        size: bytes.len(),
                        data_base64: None,
                        kind: None,
                        entries: None,
                        created: None,
                        info: None,
                        entry_infos: None,
                    }),
                    _ => Err(io::Error::from_raw_os_error(libc::EFBIG)),
                }
            }
            _ => Err(io::Error::from_raw_os_error(libc::EFBIG)),
        },
        "list" if file.data_base64.is_none() => {
            list_workspace_directory(workspace, relative).map(|(entries, entry_infos)| FileResult {
                action: "list".into(),
                path: file.path.clone(),
                destination: None,
                size: entries.len(),
                data_base64: None,
                kind: None,
                entries: Some(entries),
                created: None,
                info: None,
                entry_infos: Some(entry_infos),
            })
        }
        "stat" if file.data_base64.is_none() => {
            stat_workspace_path(workspace, relative).map(|(kind, size, info)| FileResult {
                action: "stat".into(),
                path: file.path.clone(),
                destination: None,
                size,
                data_base64: None,
                kind: Some(kind),
                entries: None,
                created: None,
                info: Some(info),
                entry_infos: None,
            })
        }
        "info" if file.data_base64.is_none() => {
            info_workspace_path(workspace, relative).map(|(kind, size, info)| FileResult {
                action: "info".into(),
                path: file.path.clone(),
                destination: None,
                size,
                data_base64: None,
                kind: Some(kind),
                entries: None,
                created: None,
                info: Some(info),
                entry_infos: None,
            })
        }
        "delete" if file.data_base64.is_none() && !relative.is_empty() => {
            delete_workspace_file(workspace, relative).map(|()| FileResult {
                action: "delete".into(),
                path: file.path.clone(),
                destination: None,
                size: 0,
                data_base64: None,
                kind: None,
                entries: None,
                created: None,
                info: None,
                entry_infos: None,
            })
        }
        "mkdir" if file.data_base64.is_none() => {
            make_workspace_directory(workspace, relative).map(|created| FileResult {
                action: "mkdir".into(),
                path: file.path.clone(),
                destination: None,
                size: 0,
                data_base64: None,
                kind: None,
                entries: None,
                created: Some(created),
                info: None,
                entry_infos: None,
            })
        }
        _ => {
            let mut result = error_result(
                &request.job_id,
                SESSION_PROTOCOL,
                "unsupported file operation".into(),
            );
            result.file_error_code = Some("invalid_request");
            return result;
        }
    };
    match operation {
        Ok(value) => {
            if matches!(file.action.as_str(), "list" | "stat" | "info")
                && serde_json::to_vec(&value).map_or(true, |encoded| encoded.len() > 256 * 1024)
            {
                let mut result = error_result(
                    &request.job_id,
                    SESSION_PROTOCOL,
                    "workspace file metadata exceeds response limit".into(),
                );
                result.file_error_code = Some("too_large");
                return result;
            }
            let mut result = success_result(&request.job_id, SESSION_PROTOCOL);
            result.file_result = Some(value);
            result
        }
        Err(error) => {
            let mut result = error_result(
                &request.job_id,
                SESSION_PROTOCOL,
                "workspace file operation failed".into(),
            );
            result.file_error_code = Some(file_error_code(&error));
            result
        }
    }
}

fn read_workspace_file(workspace: &Path, relative: &str) -> io::Result<Vec<u8>> {
    let root = File::open(workspace)?;
    let mut file = open_beneath(
        root.as_raw_fd(),
        relative,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        0,
    )?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }
    if metadata.len() > FILE_LIMIT as u64 {
        return Err(io::Error::from_raw_os_error(libc::EFBIG));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    Read::by_ref(&mut file)
        .take(FILE_LIMIT as u64 + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() > FILE_LIMIT {
        return Err(io::Error::from_raw_os_error(libc::EFBIG));
    }
    Ok(bytes)
}

fn workspace_directory(workspace: &Path, relative: &str) -> io::Result<File> {
    let root = File::open(workspace)?;
    if relative.is_empty() {
        Ok(root)
    } else {
        open_beneath(
            root.as_raw_fd(),
            relative,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
        )
    }
}

struct DirectoryStream(*mut libc::DIR);

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        unsafe { libc::closedir(self.0) };
    }
}

fn permission_text(mode: u32) -> String {
    let mut chars = ['-'; 9];
    for (index, bit) in [
        0o400, 0o200, 0o100, 0o040, 0o020, 0o010, 0o004, 0o002, 0o001,
    ]
    .iter()
    .enumerate()
    {
        if mode & bit != 0 {
            chars[index] = match index % 3 {
                0 => 'r',
                1 => 'w',
                _ => 'x',
            };
        }
    }
    for (index, special) in [(2, 0o4000), (5, 0o2000), (8, 0o1000)] {
        if mode & special != 0 {
            chars[index] = match (index, chars[index] == 'x') {
                (8, true) => 't',
                (8, false) => 'T',
                (_, true) => 's',
                _ => 'S',
            };
        }
    }
    chars.iter().collect()
}

fn owner_name(uid: u32) -> String {
    let mut entry: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buffer = [0u8; 1024];
    let mut found = std::ptr::null_mut();
    let status = unsafe {
        libc::getpwuid_r(
            uid,
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut found,
        )
    };
    if status == 0 && !found.is_null() && !entry.pw_name.is_null() {
        unsafe { CStr::from_ptr(entry.pw_name) }
            .to_string_lossy()
            .into_owned()
    } else {
        uid.to_string()
    }
}

fn group_name(gid: u32) -> String {
    let mut entry: libc::group = unsafe { std::mem::zeroed() };
    let mut buffer = [0u8; 1024];
    let mut found = std::ptr::null_mut();
    let status = unsafe {
        libc::getgrgid_r(
            gid,
            &mut entry,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut found,
        )
    };
    if status == 0 && !found.is_null() && !entry.gr_name.is_null() {
        unsafe { CStr::from_ptr(entry.gr_name) }
            .to_string_lossy()
            .into_owned()
    } else {
        gid.to_string()
    }
}

fn e2b_metadata_key_valid(key: &[u8]) -> bool {
    !key.is_empty()
        && key.len() <= 246
        && key
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(byte))
}

fn e2b_file_metadata(file: &File, symlink: bool) -> io::Result<Option<BTreeMap<String, String>>> {
    // ext4 does not support user.* attributes on symlink inodes. Never follow a
    // symlink through /proc/self/fd to inspect its target.
    if symlink {
        return Ok(None);
    }
    let path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd())).unwrap();
    let required = unsafe { libc::listxattr(path.as_ptr(), std::ptr::null_mut(), 0) };
    if required < 0 {
        return Err(io::Error::last_os_error());
    }
    if required == 0 {
        return Ok(None);
    }
    if required as usize > 16 * 1024 {
        return Err(io::Error::from_raw_os_error(libc::EFBIG));
    }
    let mut names = vec![0u8; required as usize];
    let count = unsafe { libc::listxattr(path.as_ptr(), names.as_mut_ptr().cast(), names.len()) };
    if count < 0 {
        return Err(io::Error::last_os_error());
    }
    if count as usize > names.len() || count > 0 && names[count as usize - 1] != 0 {
        return Err(io::Error::from_raw_os_error(libc::EAGAIN));
    }
    let mut metadata = BTreeMap::new();
    let mut total = 0usize;
    for full_name in names[..count as usize]
        .split(|byte| *byte == 0)
        .filter(|name| !name.is_empty())
    {
        let Some(key) = full_name.strip_prefix(b"user.e2b.") else {
            continue;
        };
        if !e2b_metadata_key_valid(key) || metadata.len() >= 16 {
            return Err(io::Error::from_raw_os_error(libc::EFBIG));
        }
        let full_name =
            CString::new(full_name).map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        let needed =
            unsafe { libc::getxattr(path.as_ptr(), full_name.as_ptr(), std::ptr::null_mut(), 0) };
        if needed < 0 {
            return Err(io::Error::last_os_error());
        }
        total = total
            .saturating_add(key.len())
            .saturating_add(needed as usize);
        if total > 16 * 1024 {
            return Err(io::Error::from_raw_os_error(libc::EFBIG));
        }
        let mut value = vec![0u8; needed as usize];
        let got = unsafe {
            libc::getxattr(
                path.as_ptr(),
                full_name.as_ptr(),
                value.as_mut_ptr().cast(),
                value.len(),
            )
        };
        if got < 0 {
            return Err(io::Error::last_os_error());
        }
        if got != needed || !value.iter().all(|byte| (0x20..=0x7e).contains(byte)) {
            return Err(io::Error::from(io::ErrorKind::InvalidData));
        }
        metadata.insert(
            String::from_utf8(key.to_vec()).unwrap(),
            String::from_utf8(value).unwrap(),
        );
    }
    if metadata.is_empty() {
        Ok(None)
    } else {
        Ok(Some(metadata))
    }
}

fn symlink_target(file: &File) -> io::Result<String> {
    let mut buffer = [0u8; 4097];
    let empty = CString::new("").unwrap();
    let length = unsafe {
        libc::readlinkat(
            file.as_raw_fd(),
            empty.as_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
        )
    };
    if length < 0 {
        return Err(io::Error::last_os_error());
    }
    if length == 0 || length as usize >= buffer.len() {
        return Err(io::Error::from_raw_os_error(libc::EFBIG));
    }
    String::from_utf8(buffer[..length as usize].to_vec())
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))
}

fn file_info_from_file(file: &File, name: &str, path: String) -> io::Result<FileInfo> {
    let metadata = file.metadata()?;
    let file_type = if metadata.is_file() {
        "file"
    } else if metadata.is_dir() {
        "directory"
    } else if metadata.file_type().is_symlink() {
        "symlink"
    } else {
        "other"
    };
    let modified_time_ms = metadata
        .mtime()
        .checked_mul(1000)
        .and_then(|seconds| seconds.checked_add(metadata.mtime_nsec() / 1_000_000))
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
    if !(0..=4_102_444_800_000).contains(&modified_time_ms) {
        return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
    }
    let mode = metadata.mode();
    Ok(FileInfo {
        name: name.to_string(),
        path,
        file_type,
        size: metadata.len(),
        mode,
        permissions: permission_text(mode),
        owner: owner_name(metadata.uid()),
        group: group_name(metadata.gid()),
        modified_time_ms,
        symlink_target: if file_type == "symlink" {
            Some(symlink_target(file)?)
        } else {
            None
        },
        metadata: e2b_file_metadata(file, file_type == "symlink")?,
    })
}

fn list_workspace_directory(
    workspace: &Path,
    relative: &str,
) -> io::Result<(Vec<String>, Vec<FileInfo>)> {
    let directory = workspace_directory(workspace, relative)?;
    let duplicate = unsafe { libc::dup(directory.as_raw_fd()) };
    if duplicate < 0 {
        return Err(io::Error::last_os_error());
    }
    let raw_stream = unsafe { libc::fdopendir(duplicate) };
    if raw_stream.is_null() {
        let error = io::Error::last_os_error();
        unsafe { libc::close(duplicate) };
        return Err(error);
    }
    let stream = DirectoryStream(raw_stream);
    let mut entries = Vec::new();
    let mut name_bytes = 0usize;
    loop {
        unsafe { *libc::__errno_location() = 0 };
        let item = unsafe { libc::readdir(stream.0) };
        if item.is_null() {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(0) {
                break;
            }
            return Err(error);
        }
        let bytes = unsafe { CStr::from_ptr((*item).d_name.as_ptr()) }.to_bytes();
        if bytes == b"." || bytes == b".." {
            continue;
        }
        if bytes.is_empty() || bytes.len() > 255 || bytes.contains(&b'/') || bytes.contains(&b'\\')
        {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        name_bytes += bytes.len();
        if entries.len() >= FILE_LIST_LIMIT || name_bytes > FILE_LIST_NAME_BYTES_LIMIT {
            return Err(io::Error::from_raw_os_error(libc::EFBIG));
        }
        let name = String::from_utf8(bytes.to_vec())
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?;
        if name.chars().any(|ch| ch.is_control()) {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        entries.push(name);
    }
    entries.sort_unstable();
    let parent_path = if relative.is_empty() {
        "/workspace".to_string()
    } else {
        format!("/workspace/{relative}")
    };
    let mut infos = Vec::with_capacity(entries.len());
    let mut resolved_entries = Vec::with_capacity(entries.len());
    for name in entries {
        let target = match open_beneath(
            directory.as_raw_fd(),
            &name,
            libc::O_PATH | libc::O_NOFOLLOW,
            0,
        ) {
            Ok(target) => target,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                continue;
            }
            Err(error) => return Err(error),
        };
        infos.push(file_info_from_file(
            &target,
            &name,
            format!("{parent_path}/{name}"),
        )?);
        resolved_entries.push(name);
    }
    Ok((resolved_entries, infos))
}

fn info_workspace_path(
    workspace: &Path,
    relative: &str,
) -> io::Result<(&'static str, usize, FileInfo)> {
    let target = if relative.is_empty() {
        File::open(workspace)?
    } else {
        let root = File::open(workspace)?;
        open_beneath(
            root.as_raw_fd(),
            relative,
            libc::O_PATH | libc::O_NOFOLLOW,
            0,
        )?
    };
    let name = relative
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("workspace");
    let path = if relative.is_empty() {
        "/workspace".to_string()
    } else {
        format!("/workspace/{relative}")
    };
    let info = file_info_from_file(&target, name, path)?;
    Ok((
        info.file_type,
        if info.file_type == "file" {
            info.size as usize
        } else {
            0
        },
        info,
    ))
}

fn stat_workspace_path(
    workspace: &Path,
    relative: &str,
) -> io::Result<(&'static str, usize, FileInfo)> {
    let result = info_workspace_path(workspace, relative)?;
    if result.0 != "file" && result.0 != "directory" {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }
    Ok(result)
}

fn delete_workspace_file(workspace: &Path, relative: &str) -> io::Result<()> {
    let root = File::open(workspace)?;
    let (parent_name, basename) = relative.rsplit_once('/').unwrap_or(("", relative));
    let parent = if parent_name.is_empty() {
        root.try_clone()?
    } else {
        open_beneath(
            root.as_raw_fd(),
            parent_name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
        )?
    };
    let target = open_beneath(
        parent.as_raw_fd(),
        basename,
        libc::O_PATH | libc::O_NOFOLLOW,
        0,
    )?;
    if !target.metadata()?.is_file() {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }
    let name = CString::new(basename).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    if unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    parent.sync_all()
}

fn make_workspace_directory(workspace: &Path, relative: &str) -> io::Result<bool> {
    let root = File::open(workspace)?;
    let mut parent = root.try_clone()?;
    let parts: Vec<&str> = relative.split('/').collect();
    if parts.is_empty() || parts.len() > 16 {
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }
    let mut created_final = false;
    for (index, part) in parts.iter().enumerate() {
        let name = CString::new(*part).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
        let made = match unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } {
            0 => true,
            _ => {
                let error = io::Error::last_os_error();
                if error.raw_os_error() != Some(libc::EEXIST) {
                    return Err(error);
                }
                false
            }
        };
        let next = open_beneath(
            parent.as_raw_fd(),
            part,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
            0,
        )?;
        if made {
            if unsafe { libc::geteuid() } == 0
                && unsafe { libc::fchown(next.as_raw_fd(), SANDBOX_UID, SANDBOX_GID) } < 0
            {
                return Err(io::Error::last_os_error());
            }
            if unsafe { libc::fchmod(next.as_raw_fd(), 0o700) } < 0 {
                return Err(io::Error::last_os_error());
            }
            next.sync_all()?;
            parent.sync_all()?;
        }
        if index + 1 == parts.len() {
            created_final = made;
        }
        parent = next;
    }
    Ok(created_final)
}

fn write_workspace_file(
    workspace: &Path,
    relative: &str,
    job_id: &str,
    bytes: &[u8],
    metadata: Option<&BTreeMap<String, String>>,
) -> io::Result<()> {
    if bytes.len() > FILE_LIMIT {
        return Err(io::Error::from_raw_os_error(libc::EFBIG));
    }
    if let Some(metadata) = metadata
        && (metadata.len() > 16
            || metadata.iter().any(|(key, value)| {
                !e2b_metadata_key_valid(key.as_bytes())
                    || !value.bytes().all(|byte| (0x20..=0x7e).contains(&byte))
            })
            || metadata
                .iter()
                .map(|(key, value)| key.len() + value.len())
                .sum::<usize>()
                > 16 * 1024)
    {
        return Err(io::Error::from_raw_os_error(libc::EFBIG));
    }
    let root = File::open(workspace)?;
    let (parent_name, basename) = relative.rsplit_once('/').unwrap_or(("", relative));
    let parent = if parent_name.is_empty() {
        root.try_clone()?
    } else {
        open_beneath(
            root.as_raw_fd(),
            parent_name,
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        )?
    };
    match open_beneath(
        root.as_raw_fd(),
        relative,
        libc::O_PATH | libc::O_NOFOLLOW,
        0,
    ) {
        Ok(existing) if !existing.metadata()?.is_file() => {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        Ok(_) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error),
    }
    let temporary = CString::new(format!(".osv-write-{job_id}"))
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let target =
        CString::new(basename).map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            temporary.as_ptr(),
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0o600,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let mut staged = unsafe { File::from_raw_fd(fd) };
    let result = (|| -> io::Result<()> {
        if unsafe { libc::geteuid() } == 0
            && unsafe { libc::fchown(staged.as_raw_fd(), SANDBOX_UID, SANDBOX_GID) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        if unsafe { libc::fchmod(staged.as_raw_fd(), 0o600) } < 0 {
            return Err(io::Error::last_os_error());
        }
        staged.write_all(bytes)?;
        if let Some(metadata) = metadata {
            for (key, value) in metadata {
                let name = CString::new(format!("user.e2b.{key}")).unwrap();
                if unsafe {
                    libc::fsetxattr(
                        staged.as_raw_fd(),
                        name.as_ptr(),
                        value.as_ptr().cast(),
                        value.len(),
                        0,
                    )
                } < 0
                {
                    return Err(io::Error::last_os_error());
                }
            }
        }
        staged.sync_all()?;
        if unsafe {
            libc::renameat(
                parent.as_raw_fd(),
                temporary.as_ptr(),
                parent.as_raw_fd(),
                target.as_ptr(),
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        parent.sync_all()?;
        Ok(())
    })();
    if result.is_err() {
        unsafe { libc::unlinkat(parent.as_raw_fd(), temporary.as_ptr(), 0) };
    }
    result
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
    run_job_stream(request, None)
}

fn run_job_stream(request: JobRequest, stream: Option<streaming::StreamWriter>) -> JobResult {
    let started = Instant::now();
    // Build the same final tenant environment, but never apply it to the
    // privileged helper. The private spec reaches only its ordinary child.
    let mut command = Command::new(&request.argv[0]);
    command
        .env_clear()
        .env("PATH", "/usr/local/bin:/usr/bin:/bin")
        .env("HOME", "/workspace")
        .env("LANG", "C.UTF-8");
    network_proxy::configure_command(&mut command);
    command.envs(&request.environment);
    let environment = command
        .get_envs()
        .filter_map(|(key, value)| {
            value.map(|value| {
                (
                    key.to_string_lossy().into_owned(),
                    value.to_string_lossy().into_owned(),
                )
            })
        })
        .collect();
    let child = match workload::Process::spawn(
        workload::Spec {
            argv: request.argv.clone(),
            environment,
            cwd: request.cwd.clone().unwrap_or_else(|| "/workspace".into()),
        },
        request.interactive_stdin || request.stdin.is_some(),
    ) {
        Ok(child) => child,
        Err(error) => {
            return error_result(
                &request.job_id,
                result_protocol(&request.protocol),
                format!("spawn {}: {error}", request.argv[0]),
            );
        }
    };
    supervise_process(child, &request, started, stream)
}

trait JobProcess {
    fn take_io(&mut self) -> (Option<ChildStdin>, Option<ChildStdout>, Option<ChildStderr>);
    fn pid(&self) -> Option<u32>;
    fn advance(&mut self) -> io::Result<Option<ExitStatus>>;
    fn terminate(&mut self) -> io::Result<()>;
    fn reaped(&self) -> bool;
    fn control_poll(&self) -> libc::pollfd;
    fn startup_error(&self) -> Option<&str> {
        None
    }
}

impl JobProcess for workload::Process {
    fn take_io(&mut self) -> (Option<ChildStdin>, Option<ChildStdout>, Option<ChildStderr>) {
        (self.stdin.take(), self.stdout.take(), self.stderr.take())
    }
    fn pid(&self) -> Option<u32> {
        workload::Process::pid(self)
    }
    fn advance(&mut self) -> io::Result<Option<ExitStatus>> {
        let complete = self.try_wait()?;
        Ok(complete.or_else(|| self.observed_status()))
    }
    fn terminate(&mut self) -> io::Result<()> {
        self.stop();
        Ok(())
    }
    fn reaped(&self) -> bool {
        self.clean()
    }
    fn startup_error(&self) -> Option<&str> {
        self.spawn_error()
    }
    fn control_poll(&self) -> libc::pollfd {
        libc::pollfd {
            fd: self.control_fd(),
            events: libc::POLLIN | if self.wants_write() { libc::POLLOUT } else { 0 },
            revents: 0,
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy)]
enum KillScope {
    ProcessGroup,
}

#[cfg(test)]
fn terminate_workload(pid: u32, scope: KillScope) -> std::io::Result<()> {
    let target = match scope {
        KillScope::ProcessGroup => -(pid as i32),
    };
    if unsafe { libc::kill(target, libc::SIGKILL) } < 0 {
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() != Some(libc::ESRCH) {
            return Err(error);
        }
    }
    let _ = pid;
    Ok(())
}

fn set_nonblocking(fd: RawFd) -> std::io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

fn drain_pipe<R: Read>(
    pipe: &mut Option<R>,
    captured: &mut CapturedOutput,
    stdout: bool,
) -> std::io::Result<()> {
    let Some(reader) = pipe.as_mut() else {
        return Ok(());
    };
    let mut buffer = [0_u8; 4096];
    // Bound work per stream so an output flood cannot starve timeout checks.
    for _ in 0..16 {
        match reader.read(&mut buffer) {
            Ok(0) => {
                *pipe = None;
                break;
            }
            Ok(count) => {
                let keep = if captured.stream.as_ref().is_some_and(|s| !s.has_capacity()) {
                    0
                } else {
                    captured.limit.saturating_sub(captured.total).min(count)
                };
                if let Some(stream) = captured.stream.as_mut() {
                    stream.emit(stdout, &buffer[..keep])?;
                }
                if stdout {
                    captured.stdout.extend_from_slice(&buffer[..keep]);
                } else {
                    captured.stderr.extend_from_slice(&buffer[..keep]);
                }
                captured.total += keep;
                captured.truncated |= keep < count;
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                *pipe = None;
                return Err(error);
            }
        }
    }
    Ok(())
}

#[cfg(test)]
fn supervise_child(
    child: Child,
    request: &JobRequest,
    started: Instant,
    scope: KillScope,
) -> JobResult {
    supervise_child_stream(child, request, started, scope, None)
}

#[cfg(test)]
fn supervise_child_stream(
    child: Child,
    request: &JobRequest,
    started: Instant,
    scope: KillScope,
    stream: Option<streaming::StreamWriter>,
) -> JobResult {
    supervise_process(DirectJobProcess { child, scope }, request, started, stream)
}

#[cfg(test)]
struct DirectJobProcess {
    child: Child,
    scope: KillScope,
}

#[cfg(test)]
impl JobProcess for DirectJobProcess {
    fn take_io(&mut self) -> (Option<ChildStdin>, Option<ChildStdout>, Option<ChildStderr>) {
        (
            self.child.stdin.take(),
            self.child.stdout.take(),
            self.child.stderr.take(),
        )
    }
    fn pid(&self) -> Option<u32> {
        Some(self.child.id())
    }
    fn advance(&mut self) -> io::Result<Option<ExitStatus>> {
        self.child.try_wait()
    }
    fn terminate(&mut self) -> io::Result<()> {
        terminate_workload(self.child.id(), self.scope)
    }
    fn reaped(&self) -> bool {
        true
    }
    fn control_poll(&self) -> libc::pollfd {
        libc::pollfd {
            fd: -1,
            events: 0,
            revents: 0,
        }
    }
}

fn supervise_process(
    mut child: impl JobProcess,
    request: &JobRequest,
    started: Instant,
    stream: Option<streaming::StreamWriter>,
) -> JobResult {
    let mut captured = CapturedOutput {
        limit: request.max_output_bytes,
        ..CapturedOutput::default()
    };
    captured.stream = stream;
    let (mut input, mut stdout, mut stderr) = child.take_io();
    let mut failure = None;
    if let Some(writer) = captured.stream.as_mut()
        && let Err(error) = writer.attach_stdin(input.take())
    {
        failure = Some(format!("configure command stdin: {error}"));
    }
    let mut announced = false;
    let mut fixed_input = None;
    if let Some(encoded) = request.stdin.as_deref() {
        let input = job_stdin::decode(encoded).and_then(|data| {
            input
                .take()
                .ok_or_else(|| io::Error::other("fixed stdin pipe unavailable"))
                .and_then(|pipe| job_stdin::FixedInput::new(pipe, data))
        });
        match input {
            Ok(input) => fixed_input = Some(input),
            Err(error) => failure = Some(format!("configure job stdin: {error}")),
        }
    }
    if let Some(pipe) = stdout.as_ref()
        && let Err(error) = set_nonblocking(pipe.as_raw_fd())
    {
        failure = Some(error.to_string());
        stdout = None;
    }
    if let Some(pipe) = stderr.as_ref()
        && let Err(error) = set_nonblocking(pipe.as_raw_fd())
    {
        failure = Some(error.to_string());
        stderr = None;
    }
    let deadline = started + Duration::from_millis(request.timeout_ms);
    let mut status = None;
    let mut timed_out = false;
    let mut drain_deadline = None;
    loop {
        if failure.is_none()
            && let Some(stream) = captured.stream.as_mut()
            && let Err(error) = stream.check_control()
        {
            failure = Some(error.to_string());
        }
        if failure.is_none()
            && let Some(input) = fixed_input.as_mut()
            && let Err(error) = input.progress()
        {
            failure = Some(format!("write job stdin: {error}"));
        }
        if drain_deadline.is_none() && failure.is_some() {
            drain_deadline = Some(Instant::now() + Duration::from_millis(500));
            fixed_input = None;
            if let Err(error) = child.terminate() {
                failure = Some(format!("terminate workload: {error}"));
            }
        }
        {
            match child.advance() {
                Ok(Some(value)) => status = Some(value),
                Ok(None) => (),
                Err(error) => {
                    failure = Some(format!("wait for command: {error}"));
                }
            }
        }
        if !announced && let Some(pid) = child.pid() {
            announced = true;
            if let Some(writer) = captured.stream.as_mut()
                && let Err(error) = writer.started(pid)
            {
                failure = Some(format!("announce command: {error}"));
            }
        }
        if failure.is_none()
            && let Some(error) = child.startup_error()
        {
            failure = Some(format!("spawn workload: {error}"));
        }
        let now = Instant::now();
        if drain_deadline.is_none() && (status.is_some() || failure.is_some() || now >= deadline) {
            timed_out = status.is_none() && failure.is_none() && now >= deadline;
            drain_deadline = Some(now + Duration::from_millis(500));
            fixed_input = None;
        }
        if drain_deadline.is_some()
            && let Err(error) = child.terminate()
        {
            failure = Some(format!("terminate workload: {error}"));
        }
        let read_output = captured.stream.is_none() || announced || status.is_some();
        if read_output {
            if let Err(error) = drain_pipe(&mut stdout, &mut captured, true) {
                failure = Some(format!("read stdout: {error}"));
            }
            if let Err(error) = drain_pipe(&mut stderr, &mut captured, false) {
                failure = Some(format!("read stderr: {error}"));
            }
        }
        if status.is_some() && drain_deadline.is_some() {
            let reaped = child.reaped();
            if stdout.is_none() && stderr.is_none() && reaped {
                break;
            }
        }
        if drain_deadline.is_some_and(|end| Instant::now() >= end) {
            failure = Some("guest workload cleanup deadline exceeded".into());
            break;
        }
        let mut polls = [
            libc::pollfd {
                fd: if read_output {
                    stdout.as_ref().map_or(-1, AsRawFd::as_raw_fd)
                } else {
                    -1
                },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: if read_output {
                    stderr.as_ref().map_or(-1, AsRawFd::as_raw_fd)
                } else {
                    -1
                },
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: fixed_input.as_ref().map_or(-1, job_stdin::FixedInput::fd),
                events: libc::POLLOUT,
                revents: 0,
            },
            child.control_poll(),
        ];
        if unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, 2) } < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                failure = Some(format!("poll output: {error}"));
            }
        }
    }
    if let Some(writer) = captured.stream.as_mut()
        && let Err(error) = writer.finish_stdin()
    {
        failure = Some(format!("finish command stdin: {error}"));
    }
    let exit_code = if child.startup_error().is_some() {
        -1
    } else {
        status
            .as_ref()
            .and_then(|value| {
                value
                    .code()
                    .or_else(|| value.signal().map(|signal| 128 + signal))
            })
            .unwrap_or(-1)
    };
    JobResult {
        proxy_revision: 1,
        protocol: result_protocol(&request.protocol),
        job_id: request.job_id.clone(),
        ok: !timed_out && failure.is_none() && status.is_some_and(|value| value.success()),
        exit_code,
        timed_out,
        duration_ms: started.elapsed().as_millis(),
        stdout: String::from_utf8_lossy(&captured.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&captured.stderr).into_owned(),
        output_truncated: captured.truncated,
        error: failure.or_else(|| timed_out.then(|| "guest command timed out".into())),
        file_result: None,
        file_error_code: None,
        binding: None,
        guest_state: None,
        remaining_lifetime_ms: None,
        pristine_revision: None,
        code_service: None,
        port_service: None,
    }
}

fn initialize_guest(pristine_mode: bool) -> Result<(), Box<dyn std::error::Error>> {
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
    for (name, target) in [
        ("/dev/fd", "/proc/self/fd"),
        ("/dev/stdin", "/proc/self/fd/0"),
        ("/dev/stdout", "/proc/self/fd/1"),
        ("/dev/stderr", "/proc/self/fd/2"),
    ] {
        if !Path::new(name).exists() {
            std::os::unix::fs::symlink(target, name)?;
        }
    }
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
    if pristine_mode {
        if Path::new("/dev/vdc").exists() {
            return Err("pristine VM cannot have a prepopulated input drive".into());
        }
        mount_required(
            "tmpfs",
            "/input",
            "tmpfs",
            libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC,
            Some("size=4m,mode=0700"),
        )?;
        if Path::new("/workspace/lost+found").exists() {
            fs::remove_dir("/workspace/lost+found")?;
        }
        if fs::read_dir("/workspace")?.next().is_some() {
            return Err("pristine workspace is not empty".into());
        }
    } else if std::path::Path::new("/dev/vdc").exists() {
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
    workload::initialize()?;
    Ok(())
}

fn mount_optional(
    source: &str,
    target: &str,
    fs_type: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
) {
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

fn mount(
    source: &str,
    target: &str,
    fs_type: &str,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> Result<(), std::io::Error> {
    let source = CString::new(source).unwrap();
    let target = CString::new(target).unwrap();
    let fs_type = CString::new(fs_type).unwrap();
    let data = data.map(|value| CString::new(value).unwrap());
    let data_ptr = data
        .as_ref()
        .map_or(std::ptr::null(), |value| value.as_ptr().cast());
    let result = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            fs_type.as_ptr(),
            flags,
            data_ptr,
        )
    };
    if result < 0 {
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

fn accept_host_vsock_until(
    listener: RawFd,
    deadline: Instant,
) -> Result<Option<File>, std::io::Error> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        let mut pollfd = libc::pollfd {
            fd: listener,
            events: libc::POLLIN,
            revents: 0,
        };
        // Keep fractional milliseconds: truncating to poll's integer timeout
        // turns the end of every service wait into a zero-timeout busy loop.
        let remaining = remaining.min(Duration::from_secs(1));
        let wait = libc::timespec {
            tv_sec: remaining.as_secs() as _,
            tv_nsec: remaining.subsec_nanos() as _,
        };
        let ready = unsafe { libc::ppoll(&mut pollfd, 1, &wait, std::ptr::null()) };
        if ready == 0 {
            continue;
        }
        if ready < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        let mut peer = SockAddrVm {
            family: 0,
            reserved: 0,
            port: 0,
            cid: 0,
            zero: [0; 4],
        };
        let mut peer_len = std::mem::size_of::<SockAddrVm>() as libc::socklen_t;
        let fd = unsafe {
            libc::accept4(
                listener,
                (&mut peer as *mut SockAddrVm).cast(),
                &mut peer_len,
                libc::SOCK_CLOEXEC,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        if peer_len as usize != std::mem::size_of::<SockAddrVm>()
            || peer.family != libc::AF_VSOCK as libc::sa_family_t
            || peer.cid != 2
        {
            unsafe { libc::close(fd) };
            continue;
        }
        set_socket_timeout(fd, libc::SO_RCVTIMEO, 5)?;
        set_socket_timeout(fd, libc::SO_SNDTIMEO, 5)?;
        return Ok(Some(unsafe { File::from_raw_fd(fd) }));
    }
}

fn set_socket_timeout(fd: RawFd, option: libc::c_int, seconds: i64) -> std::io::Result<()> {
    let timeout = libc::timeval {
        tv_sec: seconds as _,
        tv_usec: 0,
    };
    let result = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            option,
            (&timeout as *const libc::timeval).cast(),
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        )
    };
    if result < 0 {
        let error = std::io::Error::last_os_error();
        unsafe { libc::close(fd) };
        return Err(error);
    }
    Ok(())
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

fn error_result(job_id: &str, protocol: &'static str, error: String) -> JobResult {
    JobResult {
        proxy_revision: 1,
        protocol,
        job_id: job_id.into(),
        ok: false,
        exit_code: -1,
        timed_out: false,
        duration_ms: 0,
        stdout: String::new(),
        stderr: String::new(),
        output_truncated: false,
        error: Some(error),
        file_result: None,
        file_error_code: None,
        binding: None,
        guest_state: None,
        remaining_lifetime_ms: None,
        pristine_revision: None,
        code_service: None,
        port_service: None,
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
    use std::os::fd::IntoRawFd;
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixStream;

    fn request_exchange(input: &str) -> (String, ConnectionAction) {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(input.as_bytes()).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let connection = unsafe { File::from_raw_fd(server.into_raw_fd()) };
        let action = handle_connection(connection, None, Instant::now() + SESSION_MAX_AGE);
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        (response, action)
    }

    fn file_request(action: &str, path: &str, data: Option<&[u8]>) -> JobRequest {
        JobRequest {
            protocol: SESSION_PROTOCOL.into(),
            job_id: "0123456789abcdef01234567".into(),
            operation: Some("file".into()),
            argv: Vec::new(),
            timeout_ms: 0,
            max_output_bytes: 0,
            file: Some(FileRequest {
                action: action.into(),
                path: path.into(),
                destination: None,
                data_base64: data.map(|bytes| STANDARD.encode(bytes)),
                metadata: None,
            }),
            binding: None,
            prepare: None,
            environment: BTreeMap::new(),
            cwd: None,
            interactive_stdin: false,
            stdin: None,
        }
    }

    #[test]
    fn workspace_file_roundtrip_is_binary_and_atomic() {
        let workspace =
            std::env::temp_dir().join(format!("osv-file-roundtrip-{}", std::process::id()));
        fs::create_dir_all(&workspace).unwrap();
        let first = run_file(
            &file_request("write", "/workspace/item", Some(&[0, 255, 10])),
            &workspace,
        );
        assert!(first.ok, "{:?}", first.error);
        assert_eq!(first.file_result.unwrap().size, 3);
        let read = run_file(&file_request("read", "/workspace/item", None), &workspace);
        assert!(read.ok);
        assert_eq!(
            STANDARD
                .decode(read.file_result.unwrap().data_base64.unwrap())
                .unwrap(),
            [0, 255, 10]
        );
        assert!(
            run_file(
                &file_request("write", "/workspace/item", Some(b"replacement")),
                &workspace
            )
            .ok
        );
        assert_eq!(fs::read(workspace.join("item")).unwrap(), b"replacement");
        let mut labelled = file_request("write", "/workspace/item", Some(b"labelled"));
        labelled.file.as_mut().unwrap().metadata =
            Some(BTreeMap::from([("label".into(), "proof".into())]));
        assert!(run_file(&labelled, &workspace).ok);
        let labelled_info = run_file(&file_request("info", "/workspace/item", None), &workspace);
        assert_eq!(
            labelled_info
                .file_result
                .unwrap()
                .info
                .unwrap()
                .metadata
                .unwrap()["label"],
            "proof"
        );
        let mut rejected = file_request("write", "/workspace/item", Some(b"bad"));
        rejected.file.as_mut().unwrap().metadata =
            Some(BTreeMap::from([("bad key".into(), "x".into())]));
        assert!(!run_file(&rejected, &workspace).ok);
        assert_eq!(fs::read(workspace.join("item")).unwrap(), b"labelled");
        fs::write(workspace.join("large"), vec![0x5a; FILE_LIMIT]).unwrap();
        let large = run_file(&file_request("read", "/workspace/large", None), &workspace);
        assert!(
            large.ok,
            "512 KiB reads must not inherit the metadata response limit"
        );
        assert_eq!(large.file_result.unwrap().size, FILE_LIMIT);
        assert_eq!(fs::read_dir(&workspace).unwrap().count(), 2);
        fs::remove_dir_all(workspace).unwrap();
    }

    #[test]
    fn workspace_file_rejects_traversal_and_symlink_escape() {
        let workspace = std::env::temp_dir().join(format!("osv-file-deny-{}", std::process::id()));
        let outside = std::env::temp_dir().join(format!("osv-file-outside-{}", std::process::id()));
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret"), b"outside").unwrap();
        symlink(&outside, workspace.join("link")).unwrap();
        for path in [
            "/workspace/../secret",
            "/workspace/link/secret",
            "/tmp/secret",
        ] {
            let read = run_file(&file_request("read", path, None), &workspace);
            assert!(!read.ok, "unexpected read: {path}");
            let write = run_file(&file_request("write", path, Some(b"changed")), &workspace);
            assert!(!write.ok, "unexpected write: {path}");
        }
        assert_eq!(fs::read(outside.join("secret")).unwrap(), b"outside");
        fs::remove_dir_all(workspace).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn workspace_directory_creation_is_confined_and_idempotent() {
        let workspace = std::env::temp_dir().join(format!("osv-mkdir-{}", std::process::id()));
        let outside =
            std::env::temp_dir().join(format!("osv-mkdir-outside-{}", std::process::id()));
        fs::create_dir_all(&workspace).unwrap();
        fs::create_dir_all(&outside).unwrap();
        let path = "/workspace/a/b/c";
        let made = run_file(&file_request("mkdir", path, None), &workspace);
        assert!(made.ok, "{:?}", made.error);
        assert_eq!(made.file_result.unwrap().created, Some(true));
        let repeated = run_file(&file_request("mkdir", path, None), &workspace);
        assert!(repeated.ok);
        assert_eq!(repeated.file_result.unwrap().created, Some(false));
        assert!(
            run_file(
                &file_request("write", "/workspace/a/b/c/file", Some(b"ok")),
                &workspace
            )
            .ok
        );
        assert_eq!(fs::read(workspace.join("a/b/c/file")).unwrap(), b"ok");

        symlink(&outside, workspace.join("link")).unwrap();
        fs::write(workspace.join("occupied"), b"file").unwrap();
        for denied in [
            "/workspace/link/escape",
            "/workspace/occupied/child",
            "/workspace/../escape",
        ] {
            let result = run_file(&file_request("mkdir", denied, None), &workspace);
            assert!(!result.ok, "mkdir accepted {denied}");
        }
        let deep = format!("/workspace/{}", vec!["d"; 17].join("/"));
        assert_eq!(
            run_file(&file_request("mkdir", &deep, None), &workspace).file_error_code,
            Some("invalid_path")
        );
        assert_eq!(fs::read_dir(&outside).unwrap().count(), 0);
        fs::remove_dir_all(workspace).unwrap();
        fs::remove_dir_all(outside).unwrap();
    }

    #[test]
    fn file_info_remains_bound_to_open_inode_during_replacement() {
        let workspace =
            std::env::temp_dir().join(format!("osv-info-binding-{}", std::process::id()));
        fs::create_dir_all(&workspace).unwrap();
        fs::write(workspace.join("file"), b"old").unwrap();
        let path = CString::new(workspace.join("file").to_str().unwrap()).unwrap();
        let attr = CString::new("user.e2b.label").unwrap();
        assert_eq!(
            unsafe { libc::setxattr(path.as_ptr(), attr.as_ptr(), b"old".as_ptr().cast(), 3, 0) },
            0
        );
        symlink("/outside-original", workspace.join("link")).unwrap();
        let root = File::open(&workspace).unwrap();
        let file =
            open_beneath(root.as_raw_fd(), "file", libc::O_PATH | libc::O_NOFOLLOW, 0).unwrap();
        let link =
            open_beneath(root.as_raw_fd(), "link", libc::O_PATH | libc::O_NOFOLLOW, 0).unwrap();
        fs::rename(workspace.join("file"), workspace.join("old-file")).unwrap();
        fs::write(workspace.join("file"), b"new").unwrap();
        fs::remove_file(workspace.join("link")).unwrap();
        symlink("/outside-replacement", workspace.join("link")).unwrap();
        let original = file_info_from_file(&file, "file", "/workspace/file".into()).unwrap();
        assert_eq!(original.metadata.unwrap()["label"], "old");
        let original_link = file_info_from_file(&link, "link", "/workspace/link".into()).unwrap();
        assert_eq!(
            original_link.symlink_target.as_deref(),
            Some("/outside-original")
        );
        assert_eq!(fs::read(workspace.join("file")).unwrap(), b"new");
        fs::remove_dir_all(workspace).unwrap();
    }

    #[test]
    fn workspace_file_list_stat_delete_are_bounded_and_confined() {
        let workspace =
            std::env::temp_dir().join(format!("osv-file-metadata-{}", std::process::id()));
        fs::create_dir_all(workspace.join("sub")).unwrap();
        fs::write(workspace.join("sub/z"), b"three").unwrap();
        fs::write(workspace.join("sub/a"), b"one").unwrap();
        let attr_path = CString::new(workspace.join("sub/z").to_str().unwrap()).unwrap();
        let attr_name = CString::new("user.e2b.label").unwrap();
        assert_eq!(
            unsafe {
                libc::setxattr(
                    attr_path.as_ptr(),
                    attr_name.as_ptr(),
                    b"proof".as_ptr().cast(),
                    5,
                    0,
                )
            },
            0
        );
        symlink("/etc/passwd", workspace.join("sub/link")).unwrap();
        let fifo = CString::new(workspace.join("sub/pipe").to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

        let root = run_file(&file_request("list", "/workspace", None), &workspace);
        assert!(root.ok, "{:?}", root.error);
        assert_eq!(root.file_result.unwrap().entries.unwrap(), ["sub"]);
        let listed = run_file(&file_request("list", "/workspace/sub", None), &workspace);
        assert!(listed.ok, "{:?}", listed.error);
        let list_value = listed.file_result.unwrap();
        assert_eq!(list_value.entries.unwrap(), ["a", "link", "pipe", "z"]);
        let infos = list_value.entry_infos.unwrap();
        assert_eq!(infos.len(), 4);
        assert_eq!(infos[0].path, "/workspace/sub/a");
        assert_eq!(infos[1].path, "/workspace/sub/link");
        assert_eq!(infos[1].file_type, "symlink");
        assert_eq!(infos[1].symlink_target.as_deref(), Some("/etc/passwd"));
        assert_eq!(infos[2].file_type, "other");
        assert_eq!(infos[3].path, "/workspace/sub/z");
        assert_eq!(infos[3].file_type, "file");
        assert_eq!(infos[3].size, 5);
        assert_eq!(infos[3].metadata.as_ref().unwrap()["label"], "proof");
        assert_eq!(infos[3].permissions.len(), 9);
        assert!(!infos[3].owner.is_empty() && !infos[3].group.is_empty());
        assert!(infos[3].modified_time_ms > 0);
        let link_info = run_file(
            &file_request("info", "/workspace/sub/link", None),
            &workspace,
        );
        assert!(link_info.ok, "{:?}", link_info.error);
        let link_value = link_info.file_result.unwrap();
        assert_eq!(link_value.kind, Some("symlink"));
        assert_eq!(
            link_value.info.unwrap().symlink_target.as_deref(),
            Some("/etc/passwd")
        );
        let stat = run_file(&file_request("stat", "/workspace/sub/z", None), &workspace);
        assert!(stat.ok);
        let value = stat.file_result.unwrap();
        assert_eq!(value.kind, Some("file"));
        assert_eq!(value.size, 5);
        let info = value.info.unwrap();
        assert_eq!(info.name, "z");
        assert_eq!(info.path, "/workspace/sub/z");
        assert_eq!(info.size, 5);
        assert_eq!(info.mode & 0o170000, 0o100000);
        let dir = run_file(&file_request("stat", "/workspace/sub", None), &workspace);
        assert_eq!(dir.file_result.unwrap().kind, Some("directory"));

        for name in ["link", "pipe"] {
            let path = format!("/workspace/sub/{name}");
            assert_eq!(
                run_file(&file_request("stat", &path, None), &workspace).file_error_code,
                Some("denied")
            );
            assert_eq!(
                run_file(&file_request("delete", &path, None), &workspace).file_error_code,
                Some("denied")
            );
        }
        assert_eq!(
            run_file(&file_request("delete", "/workspace/sub", None), &workspace).file_error_code,
            Some("denied")
        );
        assert!(
            run_file(
                &file_request("delete", "/workspace/sub/a", None),
                &workspace
            )
            .ok
        );
        assert_eq!(
            run_file(
                &file_request("delete", "/workspace/sub/a", None),
                &workspace
            )
            .file_error_code,
            Some("not_found")
        );
        assert_eq!(
            run_file(
                &file_request("list", "/workspace/sub/link", None),
                &workspace
            )
            .file_error_code,
            Some("denied")
        );
        assert!(!run_file(&file_request("delete", "/workspace", None), &workspace).ok);
        fs::remove_dir_all(workspace).unwrap();
    }

    #[test]
    fn workspace_file_list_refuses_more_than_256_names() {
        let workspace = std::env::temp_dir().join(format!("osv-file-many-{}", std::process::id()));
        fs::create_dir_all(&workspace).unwrap();
        for index in 0..=FILE_LIST_LIMIT {
            fs::write(workspace.join(format!("f{index:03}")), b"").unwrap();
        }
        let result = run_file(&file_request("list", "/workspace", None), &workspace);
        assert_eq!(result.file_error_code, Some("too_large"));
        fs::remove_dir_all(workspace).unwrap();
    }

    fn supervised_shell(script: &str, timeout_ms: u64, limit: usize) -> JobResult {
        supervised_shell_input(script, timeout_ms, limit, None)
    }

    fn supervised_shell_input(
        script: &str,
        timeout_ms: u64,
        limit: usize,
        input: Option<&[u8]>,
    ) -> JobResult {
        supervised_shell_input_ready(script, timeout_ms, limit, input, false)
    }

    fn supervised_shell_input_ready(
        script: &str,
        timeout_ms: u64,
        limit: usize,
        input: Option<&[u8]>,
        wait_output: bool,
    ) -> JobResult {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", script])
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let child = command.spawn().unwrap();
        if wait_output {
            let mut ready = libc::pollfd {
                fd: child.stdout.as_ref().unwrap().as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            assert_eq!(unsafe { libc::poll(&mut ready, 1, 2000) }, 1);
            assert_ne!(
                ready.revents & libc::POLLIN,
                0,
                "child output was not ready"
            );
        }
        let started = Instant::now();
        if let Some(pipe) = child.stdin.as_ref() {
            assert_eq!(
                unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) },
                4096
            );
        }
        let request = JobRequest {
            protocol: PROTOCOL.into(),
            job_id: "0123456789abcdef01234567".into(),
            operation: None,
            argv: vec!["/bin/sh".into()],
            timeout_ms,
            max_output_bytes: limit,
            file: None,
            binding: None,
            prepare: None,
            environment: BTreeMap::new(),
            cwd: None,
            interactive_stdin: false,
            stdin: input.map(|data| STANDARD.encode(data)),
        };
        // Never invoke guest-wide kill from a host unit test.
        supervise_child(child, &request, started, KillScope::ProcessGroup)
    }

    #[test]
    fn fixed_job_stdin_duplex_binary_and_eof() {
        let directory = std::env::temp_dir().join(format!(
            "fc-fixed-input-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        let destination = directory.join("input");
        let input: Vec<u8> = (0..job_stdin::LIMIT).map(|n| n as u8).collect();
        let script = format!(
            "head -c 131072 /dev/zero; head -c 20000 > {}; printf eof >&2",
            destination.display()
        );
        let result = supervised_shell_input(&script, 5000, 200000, Some(&input));
        assert!(result.ok, "{:?}", result.error);
        assert_eq!(result.stdout.len(), 131072);
        assert_eq!(result.stderr, "eof");
        assert_eq!(fs::read(&destination).unwrap(), input);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn fixed_job_stdin_empty_and_early_close() {
        let empty = supervised_shell_input("head -c 1; printf eof", 1000, 4096, Some(&[]));
        assert!(empty.ok && empty.stdout == "eof", "{:?}", empty.error);
        let ignored =
            supervised_shell_input("exit 7", 1000, 4096, Some(&vec![b'x'; job_stdin::LIMIT]));
        assert_eq!(ignored.exit_code, 7);
        assert!(ignored.error.is_none() && !ignored.timed_out);
    }

    #[test]
    fn fixed_job_stdin_backpressure_keeps_deadline_live() {
        let result = supervised_shell_input_ready(
            "printf output; sleep 20",
            30,
            4096,
            Some(&vec![b'x'; job_stdin::LIMIT]),
            true,
        );
        assert!(result.timed_out && !result.ok);
        assert_eq!(result.stdout, "output");
        assert!(result.duration_ms < 1000);
    }

    #[test]
    fn fixed_job_stdin_validation() {
        let data = STANDARD.encode([0, 255, 10]);
        assert_eq!(job_stdin::decode(&data).unwrap(), [0, 255, 10]);
        for invalid in [
            "Zh==".to_owned(),
            "!".to_owned(),
            STANDARD.encode(vec![0; job_stdin::LIMIT + 1]),
        ] {
            assert!(job_stdin::decode(&invalid).is_err());
        }
        let mut request: JobRequest = serde_json::from_value(serde_json::json!({"protocol":PROTOCOL,"job_id":"0123456789abcdef01234567","argv":["/bin/true"],"timeout_ms":1000,"max_output_bytes":4096,"stdin":data})).unwrap();
        assert!(validate_request(&request).is_ok());
        for operation in ["ping", "file", "run_stream", "prepare"] {
            request.protocol = SESSION_PROTOCOL.into();
            request.operation = Some(operation.into());
            assert!(validate_request(&request).is_err());
        }
    }

    #[test]
    fn background_pipe_holder_is_terminated_after_main_exits() {
        let result = supervised_shell("sleep 20 & printf main-completed; exit 7", 5000, 4096);
        assert_eq!(result.exit_code, 7);
        assert_eq!(result.stdout, "main-completed");
        assert!(!result.timed_out && result.error.is_none());
        assert!(
            result.duration_ms < 1500,
            "background held output: {} ms",
            result.duration_ms
        );
    }

    #[test]
    fn captures_both_streams_without_blocking_on_output_flood() {
        let result = supervised_shell("printf stderr >&2; head -c 200000 /dev/zero", 5000, 4096);
        assert!(result.ok, "{:?}", result.error);
        assert_eq!(result.stdout.len() + result.stderr.len(), 4096);
        assert!(result.output_truncated);
    }

    #[test]
    fn terminates_workload_at_guest_deadline() {
        let result = supervised_shell("sleep 20", 30, 4096);
        assert!(result.timed_out && !result.ok);
        assert!(result.duration_ms < 1000);
    }

    #[test]
    fn known_exit_status_takes_priority_over_late_timeout_observation() {
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "exit 7"])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(())
                }
            });
        }
        let mut child = command.spawn().unwrap();
        assert_eq!(child.wait().unwrap().code(), Some(7));
        let request:JobRequest=serde_json::from_value(serde_json::json!({"protocol":PROTOCOL,
            "job_id":"0123456789abcdef01234567","argv":["/bin/sh"],"timeout_ms":30,"max_output_bytes":1024})).unwrap();
        let result = supervise_child(
            child,
            &request,
            Instant::now() - Duration::from_secs(1),
            KillScope::ProcessGroup,
        );
        assert!(
            !result.timed_out,
            "known completed process was classified as a timeout"
        );
        assert!(result.error.is_none());
        assert_eq!(result.exit_code, 7);
    }

    #[test]
    fn workload_owner_is_rejected_outside_guest_pid_one() {
        assert_ne!(unsafe { libc::getpid() }, 1);
        let error = workload::initialize().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn validates_protocol_and_job_id() {
        let request = JobRequest {
            protocol: PROTOCOL.into(),
            job_id: "0123456789abcdef01234567".into(),
            operation: None,
            argv: vec!["/bin/true".into()],
            timeout_ms: 1000,
            max_output_bytes: 4096,
            file: None,
            binding: None,
            prepare: None,
            environment: BTreeMap::new(),
            cwd: None,
            interactive_stdin: false,
            stdin: None,
        };
        assert!(validate_request(&request).is_ok());
    }

    #[test]
    fn rejects_unbounded_output() {
        let request = JobRequest {
            protocol: PROTOCOL.into(),
            job_id: "0123456789abcdef01234567".into(),
            operation: None,
            argv: vec!["/bin/true".into()],
            timeout_ms: 1000,
            max_output_bytes: usize::MAX,
            file: None,
            binding: None,
            prepare: None,
            environment: BTreeMap::new(),
            cwd: None,
            interactive_stdin: false,
            stdin: None,
        };
        assert!(validate_request(&request).is_err());
    }

    #[test]
    fn session_ping_keeps_guest_alive_and_shutdown_powers_off() {
        let id = "0123456789abcdef01234567";
        let (ping, action) = request_exchange(&format!(
            "{{\"protocol\":\"{SESSION_PROTOCOL}\",\"operation\":\"ping\",\"job_id\":\"{id}\"}}\n"
        ));
        assert_eq!(action, ConnectionAction::Continue);
        assert!(ping.starts_with(RESULT_PREFIX));
        let result: serde_json::Value =
            serde_json::from_str(ping.trim().strip_prefix(RESULT_PREFIX).unwrap()).unwrap();
        assert_eq!(result["protocol"], SESSION_PROTOCOL);
        assert_eq!(result["job_id"], id);
        assert_eq!(result["ok"], true);

        let (shutdown, action) = request_exchange(&format!(
            "{{\"protocol\":\"{SESSION_PROTOCOL}\",\"operation\":\"shutdown\",\"job_id\":\"{id}\"}}\n"
        ));
        assert_eq!(action, ConnectionAction::Poweroff);
        assert!(shutdown.contains("\"ok\":true"));
    }

    #[test]
    fn malformed_session_request_cannot_shutdown_guest() {
        let (response, action) = request_exchange(&format!(
            "{{\"protocol\":\"{SESSION_PROTOCOL}\",\"operation\":\"shutdown\",\"job_id\":\"0123456789abcdef01234567\",\"argv\":[\"/bin/sh\"]}}\n"
        ));
        assert_eq!(action, ConnectionAction::Continue);
        assert!(response.contains("\"ok\":false"));
        let (response, action) = request_exchange(&format!(
            "{{\"protocol\":\"{SESSION_PROTOCOL}\",\"operation\":\"unsupported\",\"job_id\":\"0123456789abcdef01234567\"}}\n"
        ));
        assert_eq!(action, ConnectionAction::Continue);
        assert!(response.contains("invalid session operation"));
    }

    #[test]
    fn expired_session_rejects_request_and_powers_off() {
        let (mut client, server) = UnixStream::pair().unwrap();
        client.write_all(b"{\"protocol\":\"fc-agent/v2\",\"operation\":\"ping\",\"job_id\":\"0123456789abcdef01234567\"}\n").unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let connection = unsafe { File::from_raw_fd(server.into_raw_fd()) };
        let action = handle_connection(connection, None, Instant::now());
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        assert_eq!(action, ConnectionAction::Poweroff);
        assert!(response.contains("session lifetime expired"));
    }

    #[test]
    fn v1_request_still_powers_off_after_result() {
        let (response, action) = request_exchange(&format!(
            "{{\"protocol\":\"{PROTOCOL}\",\"job_id\":\"0123456789abcdef01234567\",\"argv\":[\"/missing\"],\"timeout_ms\":1000,\"max_output_bytes\":4096}}\n"
        ));
        assert_eq!(action, ConnectionAction::Poweroff);
        assert!(response.contains("\"protocol\":\"fc-agent/v1\""));
    }

    #[test]
    fn oversized_frame_is_rejected_without_executing() {
        let (mut client, server) = UnixStream::pair().unwrap();
        let writer = thread::spawn(move || {
            let result = client.write_all("x".repeat(REQUEST_LIMIT as usize).as_bytes());
            if result.is_ok() {
                let _ = client.write_all(b"\n");
            }
            let _ = client.shutdown(std::net::Shutdown::Write);
            result
        });
        let connection = unsafe { File::from_raw_fd(server.into_raw_fd()) };
        let action = handle_connection(connection, None, Instant::now() + SESSION_MAX_AGE);
        if let Err(error) = writer.join().unwrap() {
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        }
        assert_eq!(action, ConnectionAction::Continue);
    }
}
