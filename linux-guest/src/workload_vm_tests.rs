//! Runs the actual command/stream supervisor under isolated guest PID1.
use super::*;
use std::os::fd::IntoRawFd;
use std::os::unix::net::UnixStream;

fn request(script: &str, stream: bool) -> JobRequest {
    serde_json::from_value(serde_json::json!({"protocol":SESSION_PROTOCOL,
        "job_id":"0123456789abcdef01234567", "operation":if stream {"run_stream"} else {"run"},
        "argv":["/bin/bash","-c",script],"timeout_ms":5000,"max_output_bytes":4096}))
    .unwrap()
}

fn run(script: &str) -> JobResult {
    let request = request(script, false);
    validate_request(&request).unwrap();
    run_job(request)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Input {
    None,
    Bytes,
    AfterClose,
}

fn stream(script: &str, cancel: bool, input: Input) -> (JobResult, Vec<String>) {
    let (mut client, server) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let reader = std::thread::spawn(move || {
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut frames = Vec::new();
        let mut line = String::new();
        let mut sent_after_close = false;
        let mut output = Vec::new();
        while reader.read_line(&mut line).unwrap() != 0 {
            if line.starts_with("FC_AGENT_STARTED ") {
                if cancel {
                    client.write_all(b"cancel\n").unwrap();
                }
                if input == Input::Bytes {
                    let value = serde_json::json!({"protocol":SESSION_PROTOCOL,"job_id":"0123456789abcdef01234567",
                        "sequence":1,"data_base64":STANDARD.encode(b"input\0bytes"),"close":false});
                    writeln!(client, "{value}").unwrap();
                }
            }
            if input == Input::AfterClose
                && let Some(event) = line.strip_prefix(streaming::EVENT_PREFIX)
            {
                let event: serde_json::Value = serde_json::from_str(event).unwrap();
                if event["stream"] == "stdout" {
                    output.extend(
                        STANDARD
                            .decode(event["data_base64"].as_str().unwrap())
                            .unwrap(),
                    );
                    if !sent_after_close && output.windows(6).any(|value| value == b"closed") {
                        let value = serde_json::json!({"protocol":SESSION_PROTOCOL,"job_id":"0123456789abcdef01234567",
                            "sequence":1,"data_base64":STANDARD.encode(b"unused"),"close":false});
                        writeln!(client, "{value}").unwrap();
                        sent_after_close = true;
                    }
                }
            }
            if input != Input::None && line.starts_with("FC_AGENT_STDIN ") {
                let value: serde_json::Value =
                    serde_json::from_str(line.trim_start_matches("FC_AGENT_STDIN ")).unwrap();
                if input == Input::AfterClose {
                    assert_eq!(value["error_code"], "stdin_closed");
                    assert_eq!(value["written_bytes"], 0);
                    assert_eq!(value["closed"], true);
                    client.write_all(b"cancel\n").unwrap();
                } else if value["sequence"] == 1 {
                    let value = serde_json::json!({"protocol":SESSION_PROTOCOL,"job_id":"0123456789abcdef01234567",
                        "sequence":2,"data_base64":"","close":true});
                    writeln!(client, "{value}").unwrap();
                }
            }
            frames.push(std::mem::take(&mut line));
        }
        frames
    });
    let mut request = request(script, true);
    request.interactive_stdin = input != Input::None;
    validate_request(&request).unwrap();
    let writer = streaming::StreamWriter::new(
        unsafe { File::from_raw_fd(server.into_raw_fd()) },
        &request,
        vec![],
    )
    .unwrap();
    let result = run_job_stream(request, Some(writer));
    (result, reader.join().unwrap())
}

pub(super) fn setup_guest() {
    assert_eq!(
        unsafe { libc::getpid() },
        1,
        "never mount guest filesystems on a host test process"
    );
    for path in ["/proc", "/dev", "/run", "/tmp", "/workspace"] {
        fs::create_dir_all(path).unwrap();
    }
    mount_required("proc", "/proc", "proc", 0, None).unwrap();
    mount_required("devtmpfs", "/dev", "devtmpfs", 0, None).unwrap();
    mount_required("tmpfs", "/run", "tmpfs", 0, Some("size=16m,mode=0755")).unwrap();
    mount_required("tmpfs", "/tmp", "tmpfs", 0, Some("size=32m,mode=1777")).unwrap();
    mount_required(
        "tmpfs",
        "/workspace",
        "tmpfs",
        0,
        Some("size=64m,mode=0777"),
    )
    .unwrap();
    workload::initialize().unwrap();
    osv_runtime_allocator::initialize();
}

#[test]
#[ignore = "requires isolated guest PID1, real cgroup v2 and the production supervisor"]
fn actual_command_pipeline_at_pid_one() {
    setup_guest();
    let result = run("printf stdout; printf stderr >&2; exit 7");
    assert_eq!(
        (
            result.exit_code,
            result.stdout.as_str(),
            result.stderr.as_str()
        ),
        (7, "stdout", "stderr")
    );
    assert!(!result.ok && result.error.is_none());
    println!("PASS agent-pipeline-nonzero-and-both-streams");

    let mut input = request("cat > /workspace/binary; printf done", false);
    input.stdin = Some(STANDARD.encode([0, 255, 10]));
    let result = run_job(input);
    assert!(result.ok, "{:?}", result.error);
    assert_eq!(result.stdout, "done");
    assert_eq!(fs::read("/workspace/binary").unwrap(), [0, 255, 10]);
    let result = run("head -c 200000 /dev/zero");
    assert!(result.ok && result.output_truncated);
    assert_eq!(result.stdout.len(), 4096);
    println!("PASS agent-pipeline-fixed-binary-stdin-and-output-budget");

    let (result, frames) = stream("printf '%s' \"$$\"; printf stderr >&2", false, Input::None);
    assert!(result.ok, "{:?}", result.error);
    let first = frames
        .first()
        .unwrap()
        .trim_start_matches("FC_AGENT_STARTED ");
    let started: serde_json::Value = serde_json::from_str(first).unwrap();
    assert_eq!(result.stdout, started["pid"].as_u64().unwrap().to_string());
    let events: Vec<serde_json::Value> = frames
        .iter()
        .filter_map(|frame| frame.strip_prefix(streaming::EVENT_PREFIX))
        .map(|value| serde_json::from_str(value).unwrap())
        .collect();
    for (index, event) in events.iter().enumerate() {
        assert_eq!(event["sequence"], index as u64 + 1);
    }
    assert_eq!(result.stderr, "stderr");
    println!("PASS agent-pipeline-started-real-pid-precedes-ordered-output");

    let (result, frames) = stream("cat; printf eof >&2", false, Input::Bytes);
    assert!(result.ok, "{:?}", result.error);
    assert_eq!(result.stdout.as_bytes(), b"input\0bytes");
    assert_eq!(result.stderr, "eof");
    assert!(
        frames
            .iter()
            .any(|frame| frame.starts_with("FC_AGENT_STDIN ") && frame.contains("\"closed\":true"))
    );
    println!("PASS agent-pipeline-interactive-input-ack-and-eof");

    let (result, frames) = stream(
        "exec 0<&-; printf closed; sleep 30",
        false,
        Input::AfterClose,
    );
    assert!(!result.ok && result.error.as_deref().unwrap().contains("cancel"));
    assert!(frames.iter().any(|frame| frame.starts_with("FC_AGENT_STDIN ")
        && frame.contains("\"stdin_closed\"")));
    println!("PASS agent-pipeline-closed-target-stdin-is-rejected");

    for _ in 0..32 {
        let mut denied = request("printf forbidden", false);
        denied.cwd = Some("/proc/1/fd".into());
        let result = run_job(denied);
        assert!(!result.ok && result.exit_code == -1 && !result.timed_out);
        assert!(
            result
                .error
                .as_deref()
                .unwrap()
                .starts_with("spawn workload:")
        );
        assert!(!workload::unusable(), "denied cwd poisoned the guest");
        assert!(run("printf continued").ok);
    }
    println!("PASS agent-pipeline-spawn-error-cleanup-and-reuse");

    let (result, _) = stream("sleep 30", true, Input::None);
    assert!(!result.ok && result.error.as_deref().unwrap().contains("cancel"));
    assert!(run("printf usable").ok);
    let mut timeout = request("sleep 30", false);
    timeout.timeout_ms = 300;
    let result = run_job(timeout);
    assert!(
        result.timed_out && !result.ok && result.duration_ms < 2000,
        "{:?}",
        result.error
    );
    assert!(run("printf reused").ok);
    println!("PASS agent-pipeline-cancel-timeout-cleanup-and-reuse");

    assert!(!workload::unusable());
    assert_eq!(
        fs::read_dir("/run/osv-workloads")
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with('w'))
            .count(),
        0
    );
    println!("RUST_AGENT_WORKLOAD_PIPELINE_PASS");
    unsafe {
        libc::sync();
        libc::reboot(libc::LINUX_REBOOT_CMD_POWER_OFF);
    }
    loop {
        std::thread::park();
    }
}

static FATAL_FAULT_ARMED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn observed_fatal_reset() -> ! {
    assert!(FATAL_FAULT_ARMED.load(std::sync::atomic::Ordering::Acquire));
    assert!(workload::unusable());
    println!("RUST_AGENT_FATAL_SUPERVISION_RESET");
    poweroff()
}

#[test]
#[ignore = "requires isolated guest PID1; deliberately resets this VM"]
fn actual_fatal_helper_resets_vm() {
    setup_guest();
    workload::install_failure_handler(observed_fatal_reset).unwrap();
    let mut child = workload::Process::spawn(
        workload::Spec {
            argv: vec!["/bin/bash".into(), "-c".into(), "sleep 30".into()],
            environment: BTreeMap::from([("PATH".into(), "/bin".into())]),
            cwd: "/workspace".into(),
        },
        false,
    )
    .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    while child.pid().is_none() {
        assert!(child.try_wait().unwrap().is_none());
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(1));
    }
    let helper = fs::read_dir("/proc")
        .unwrap()
        .filter_map(Result::ok)
        .find_map(|entry| {
            let pid = entry.file_name().to_string_lossy().parse::<u32>().ok()?;
            let command = fs::read(entry.path().join("cmdline")).ok()?;
            (pid > 1
                && entry.metadata().ok()?.uid() == 0
                && command.starts_with(workload::SUPERVISOR_PATH.as_bytes())
                && command.ends_with(b"\0--workload-supervisor\0"))
            .then_some(pid)
        })
        .unwrap();
    let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, helper, 0) };
    assert!(fd >= 0);
    let fd = unsafe { File::from_raw_fd(fd as i32) };
    assert_eq!(
        unsafe {
            libc::syscall(
                libc::SYS_pidfd_send_signal,
                fd.as_raw_fd(),
                libc::SIGKILL,
                std::ptr::null::<libc::siginfo_t>(),
                0,
            )
        },
        0
    );
    FATAL_FAULT_ARMED.store(true, std::sync::atomic::Ordering::Release);
    println!("RUST_AGENT_FATAL_HELPER_KILLED");
    loop {
        assert!(
            child.try_wait().unwrap().is_none(),
            "fatal callback must reset VM before returning"
        );
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(1));
    }
}
