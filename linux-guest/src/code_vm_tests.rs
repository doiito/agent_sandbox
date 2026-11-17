//! Native policy tests and real PID1 service/handler integration.
use super::*;
use firecracker_linux_agent::code_context::{
    self as code, Context, Event, ExecutionPage, ExecutionStatus, Language,
    Request as CommandRequest, Response, State,
};
use std::os::fd::IntoRawFd;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

static NEXT: AtomicU64 = AtomicU64::new(1);
fn id() -> String {
    format!("{:024x}", NEXT.fetch_add(1, Ordering::Relaxed))
}
fn local_accept(listener: RawFd, deadline: Instant) -> io::Result<Option<File>> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(None);
        }
        let mut fd = libc::pollfd {
            fd: listener,
            events: libc::POLLIN,
            revents: 0,
        };
        let result = unsafe { libc::poll(&mut fd, 1, remaining.as_millis().max(1) as i32) };
        if result == 0 {
            return Ok(None);
        }
        if result < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            return Err(error);
        }
        let raw = unsafe {
            libc::accept4(
                listener,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                libc::SOCK_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        return Ok(Some(unsafe { File::from_raw_fd(raw) }));
    }
}
fn start() -> (Arc<code_service::Service>, String) {
    let path = format!("/run/code-{}.sock", id());
    let listener = UnixListener::bind(&path).unwrap();
    let listener = unsafe { File::from_raw_fd(listener.into_raw_fd()) };
    let service = code_service::Service::start(
        listener,
        local_accept,
        code::Options::packaged(Instant::now() + Duration::from_secs(900)),
        Some(Language::Python),
    )
    .unwrap();
    (Arc::new(service), path)
}
fn envelope(binding: Option<&pristine::Binding>, request: CommandRequest) -> code_service::Request {
    code_service::Request {
        protocol: code_service::PROTOCOL.into(),
        session_id: "a".repeat(24),
        nonce: format!("{:064x}", NEXT.fetch_add(1, Ordering::Relaxed)),
        binding: binding.cloned(),
        request,
    }
}
fn exchange(path: &str, request: &code_service::Request) -> code_service::Reply {
    let mut stream = UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    writeln!(stream, "{}", serde_json::to_string(request).unwrap()).unwrap();
    let mut line = String::new();
    BufReader::new(stream).read_line(&mut line).unwrap();
    let reply: code_service::Reply =
        serde_json::from_str(line.strip_prefix(code_service::PREFIX).unwrap()).unwrap();
    assert_eq!(reply.protocol, request.protocol);
    assert_eq!(reply.session_id, request.session_id);
    assert_eq!(reply.nonce, request.nonce);
    assert_eq!(reply.binding, request.binding);
    assert_ne!(reply.error.is_some(), reply.response.is_some());
    reply
}
fn call(path: &str, binding: Option<&pristine::Binding>, request: CommandRequest) -> Response {
    let reply = exchange(path, &envelope(binding, request));
    assert!(reply.error.is_none(), "{:?}", reply.error);
    reply.response.unwrap()
}
fn context(response: Response) -> Context {
    if let Response::Context(context) = response {
        context
    } else {
        panic!("{response:?}")
    }
}
fn ready(path: &str, binding: Option<&pristine::Binding>, id: &str, generation: u64) -> Context {
    let deadline = Instant::now() + Duration::from_secs(40);
    loop {
        let context = context(call(
            path,
            binding,
            CommandRequest::Info {
                context_id: id.into(),
            },
        ));
        assert_ne!(context.state, State::Failed, "{context:?}");
        if context.state == State::Idle && context.generation == generation {
            return context;
        }
        assert!(Instant::now() < deadline, "{context:?}");
        thread::sleep(Duration::from_millis(5));
    }
}
fn page(path: &str, binding: Option<&pristine::Binding>, id: &str, after: u64) -> ExecutionPage {
    if let Response::Execution(page) = call(
        path,
        binding,
        CommandRequest::Execution {
            execution_id: id.into(),
            after,
        },
    ) {
        page
    } else {
        panic!("execution page expected")
    }
}
fn finished(path: &str, binding: Option<&pristine::Binding>, id: &str) -> ExecutionPage {
    let deadline = Instant::now() + Duration::from_secs(90);
    let mut events = Vec::new();
    let mut after = 0;
    loop {
        let mut page = page(path, binding, id, after);
        assert!(!page.events_evicted);
        for event in &page.events {
            assert_eq!(event.sequence, after + 1);
            after = event.sequence;
        }
        events.append(&mut page.events);
        if page.status != ExecutionStatus::Running && after == page.last_sequence {
            assert!(matches!(events.first().unwrap().event, Event::Started));
            assert!(matches!(
                events.last().unwrap().event,
                Event::Finished { .. }
            ));
            assert_eq!(
                events
                    .iter()
                    .filter(|e| matches!(e.event, Event::Finished { .. }))
                    .count(),
                1
            );
            page.events = events;
            return page;
        }
        assert!(Instant::now() < deadline, "{page:?}");
        thread::sleep(Duration::from_millis(5));
    }
}
fn submit(
    path: &str,
    binding: Option<&pristine::Binding>,
    context: &Context,
    source: &str,
) -> String {
    let id = id();
    let source = source.replace("'RUNNING'", &format!("'RUNNING-{id}'"));
    assert!(matches!(
        call(
            path,
            binding,
            CommandRequest::Execute {
                context_id: context.id.clone(),
                generation: context.generation,
                execution_id: id.clone(),
                code: source,
                environment: BTreeMap::new(),
                timeout_ms: 0
            }
        ),
        Response::Accepted
    ));
    id
}
fn execute(
    path: &str,
    binding: Option<&pristine::Binding>,
    context: &Context,
    source: &str,
) -> ExecutionPage {
    finished(path, binding, &submit(path, binding, context, source))
}
fn output(page: &ExecutionPage) -> Vec<u8> {
    page.events
        .iter()
        .flat_map(|e| match &e.event {
            Event::Stdout { data } => STANDARD.decode(data).unwrap(),
            _ => Vec::new(),
        })
        .collect()
}
fn result(page: &ExecutionPage) -> &str {
    assert_eq!(page.status, ExecutionStatus::Completed, "{page:?}");
    assert!(
        !page
            .events
            .iter()
            .any(|e| matches!(e.event, Event::Error { .. })),
        "{page:?}"
    );
    page.events
        .iter()
        .find_map(|e| match &e.event {
            Event::Result {
                data,
                is_main_result: true,
            } => data["text/plain"].as_str(),
            _ => None,
        })
        .unwrap()
}
fn entered(path: &str, binding: Option<&pristine::Binding>, id: &str) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let page = page(path, binding, id, 0);
        if output(&page)
            .windows(33)
            .any(|b| b == format!("RUNNING-{id}\n").as_bytes())
        {
            return;
        }
        assert_eq!(page.status, ExecutionStatus::Running, "{page:?}");
        assert!(Instant::now() < deadline);
        thread::sleep(Duration::from_millis(5));
    }
}
fn main_rpc(
    runtime: pristine::Runtime,
    service: Arc<code_service::Service>,
    watch: Option<Arc<file_watch::Service>>,
    request: serde_json::Value,
    after: impl FnOnce(&serde_json::Value),
) -> (pristine::Runtime, ConnectionAction, serde_json::Value) {
    let (mut client, server) = UnixStream::pair().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    let worker = thread::spawn(move || {
        let mut runtime = runtime;
        let action = handle_connection_services(
            unsafe { File::from_raw_fd(server.into_raw_fd()) },
            None,
            Instant::now() + Duration::from_secs(900),
            &mut runtime,
            watch.as_deref(),
            Some(&service),
        );
        (runtime, action)
    });
    writeln!(client, "{request}").unwrap();
    let mut line = String::new();
    BufReader::new(client).read_line(&mut line).unwrap();
    let reply: serde_json::Value =
        serde_json::from_str(line.strip_prefix(RESULT_PREFIX).unwrap()).unwrap();
    after(&reply);
    let (runtime, action) = worker.join().unwrap();
    (runtime, action, reply)
}
fn ping(protocol: &str) -> serde_json::Value {
    serde_json::json!({"protocol":protocol,"job_id":id(),"operation":"ping"})
}
fn wait(predicate: impl Fn() -> bool, seconds: u64) {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    while !predicate() {
        assert!(Instant::now() < deadline, "condition timed out");
        thread::sleep(Duration::from_millis(5));
    }
}
fn zero_groups() {
    wait(
        || {
            fs::read_dir("/run/osv-workloads")
                .unwrap()
                .filter_map(Result::ok)
                .all(|entry| !entry.file_name().to_string_lossy().starts_with('w'))
        },
        20,
    );
    assert!(!workload::unusable());
}
fn reset_input() {
    let path = CString::new("/input").unwrap();
    assert_eq!(unsafe { libc::umount(path.as_ptr()) }, 0);
    mount_required(
        "tmpfs",
        "/input",
        "tmpfs",
        libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC,
        Some("size=4m,mode=0700"),
    )
    .unwrap();
}

#[test]
#[ignore = "requires real guest PID1, ext4 /dev/vdb, cgroup v2 and packaged interpreters"]
fn actual_session_code_service_at_pid_one() {
    assert_eq!(unsafe { libc::getpid() }, 1);
    std::panic::set_hook(Box::new(|info| {
        eprintln!("CODE_SERVICE_FAIL: {info}");
        poweroff();
    }));
    workload::install_failure_handler(poweroff).unwrap();
    initialize_guest(true).unwrap();
    osv_runtime_allocator::initialize();
    let mut filesystem: libc::statfs = unsafe { std::mem::zeroed() };
    assert_eq!(
        unsafe { libc::statfs(c"/workspace".as_ptr(), &mut filesystem) },
        0
    );
    assert_eq!(filesystem.f_type, 0xef53);
    assert_eq!(fs::metadata("/workspace").unwrap().uid(), SANDBOX_UID);
    assert_eq!(fs::metadata("/workspace").unwrap().mode() & 0o777, 0o700);
    let failed_listener = UnixListener::bind("/run/code-failed.sock").unwrap();
    assert!(
        code_service::Service::start(
            unsafe { File::from_raw_fd(failed_listener.into_raw_fd()) },
            local_accept,
            code::Options {
                kernel_directory: "/validation/missing-kernels".into(),
                hard_deadline: Instant::now() + Duration::from_secs(90)
            },
            Some(Language::Python)
        )
        .is_err()
    );
    zero_groups();
    println!("PASS code-service-prewarm-failure-rejects-start-and-reaps-helper");
    let (service, path) = start();
    let mut python = service.prewarmed_context().unwrap().clone();
    assert_eq!(python.state, State::Idle);
    assert!(Path::new(&format!("/proc/{}", python.pid.unwrap())).exists());
    assert_eq!(
        service.readiness().unwrap().kernel_protocol,
        code::KERNEL_PROTOCOL
    );
    assert_eq!(fs::read_dir("/workspace").unwrap().count(), 0);
    assert_eq!(
        exchange(&path, &envelope(None, CommandRequest::List {}))
            .error
            .unwrap()
            .code,
        "unsupported"
    );
    let (_, _, pristine_ping) = main_rpc(
        pristine::Runtime::Pristine,
        service.clone(),
        None,
        ping(pristine::PROTOCOL),
        |reply| {
            assert_eq!(reply["guest_state"], "pristine");
            assert_eq!(
                reply["code_service"]["kernel_protocol"],
                code::KERNEL_PROTOCOL
            );
            assert_eq!(
                exchange(&path, &envelope(None, CommandRequest::List {}))
                    .error
                    .unwrap()
                    .code,
                "unsupported"
            );
        },
    );
    assert!(pristine_ping["ok"].as_bool().unwrap());
    println!(
        "PASS code-service-real-ext4-bootstrap-prewarm-ready-and-pristine-ping-denies-control"
    );

    let watch_path = "/run/code-watch.sock";
    let listener = UnixListener::bind(watch_path).unwrap();
    let watch = Arc::new(
        file_watch::Service::with_listener(
            Path::new("/workspace"),
            &pristine::Runtime::Legacy,
            Instant::now() + Duration::from_secs(900),
            unsafe { File::from_raw_fd(listener.into_raw_fd()) },
            local_accept,
        )
        .unwrap(),
    );
    main_rpc(
        pristine::Runtime::Legacy,
        service.clone(),
        Some(watch.clone()),
        ping(SESSION_PROTOCOL),
        |reply| {
            assert_eq!(reply["ok"], true);
            assert_eq!(reply["code_service"]["prewarm_language"], "python");
            let current = context(call(
                &path,
                None,
                CommandRequest::Default {
                    language: Language::Python,
                },
            ));
            assert_eq!(current.id, python.id);
        },
    );
    let mut wrong = envelope(None, CommandRequest::List {});
    wrong.session_id = "b".repeat(24);
    assert_eq!(
        exchange(&path, &wrong).error.unwrap().code,
        "invalid_binding"
    );
    assert_eq!(
        result(&execute(
            &path,
            None,
            &python,
            "import os\nanswer=40\n(os.getuid(),os.getcwd())"
        )),
        "(10000, '/workspace')"
    );
    assert_eq!(result(&execute(&path, None, &python, "answer+2")), "42");
    println!(
        "PASS code-service-legacy-ack-authorizes-warm-default-and-pins-session-with-real-user"
    );

    let cancelled = id();
    call(
        &path,
        None,
        CommandRequest::Cancel {
            context_id: python.id.clone(),
            generation: python.generation,
            execution_id: cancelled.clone(),
        },
    );
    let receipt = page(&path, None, &cancelled, 0);
    assert_eq!(receipt.status, ExecutionStatus::Cancelled);
    assert_eq!(receipt.failure.as_deref(), Some("cancelled_before_submit"));
    assert_eq!(receipt.events.len(), 1);
    assert!(matches!(
        receipt.events[0].event,
        Event::Finished {
            status: ExecutionStatus::Cancelled,
            context_usable: true
        }
    ));
    let late = envelope(
        None,
        CommandRequest::Execute {
            context_id: python.id.clone(),
            generation: python.generation,
            execution_id: cancelled.clone(),
            code: "open('/workspace/late-submit','w').write('must-not-run')".into(),
            environment: BTreeMap::new(),
            timeout_ms: 60000,
        },
    );
    assert_eq!(exchange(&path, &late).error.unwrap().code, "conflict");
    assert!(!Path::new("/workspace/late-submit").exists());
    assert_eq!(page(&path, None, &cancelled, 0).events.len(), 1);
    println!(
        "PASS code-service-cancel-before-submit-blocks-delayed-admission-without-started-event"
    );
    let mut watch_client = UnixStream::connect(watch_path).unwrap();
    watch_client
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    writeln!(watch_client,"{}",serde_json::json!({"protocol":"fc-watch/v1","session_id":"a".repeat(24),"watch_id":id(),"nonce":"b".repeat(64),"path":"/workspace","recursive":false,"timeout_ms":10000})).unwrap();
    let mut watch_reader = BufReader::new(watch_client);
    let mut line = String::new();
    watch_reader.read_line(&mut line).unwrap();
    assert!(line.contains("\"kind\":\"ready\""), "{line}");
    let shell_service = service.clone();
    let shell_watch = watch.clone();
    let shell = thread::spawn(move || {
        main_rpc(
            pristine::Runtime::Legacy,
            shell_service,
            Some(shell_watch),
            serde_json::json!({"protocol":SESSION_PROTOCOL,"job_id":id(),"operation":"run","argv":["/bin/bash","-c","printf started > /workspace/shell-started; while [ ! -f /workspace/shell-release ]; do sleep .01; done; printf shell-done"],"timeout_ms":20000,"max_output_bytes":4096}),
            |_| {},
        )
    });
    wait(|| Path::new("/workspace/shell-started").exists(), 10);
    execute(
        &path,
        None,
        &python,
        "from pathlib import Path\nPath('/workspace/code-watched').write_text('from-code')",
    );
    loop {
        line.clear();
        watch_reader.read_line(&mut line).unwrap();
        if line.contains("code-watched") {
            break;
        }
        assert!(!line.contains("\"kind\":\"end\""), "{line}");
    }
    fs::write("/workspace/shell-release", "go").unwrap();
    let (_, _, shell_result) = shell.join().unwrap();
    assert_eq!(shell_result["stdout"], "shell-done");
    drop(watch_reader);
    println!("PASS code-service-code-shell-and-real-inotify-coexist-through-main-handler");

    let mut nodes = Vec::new();
    for language in [Language::Javascript, Language::Typescript] {
        let context = context(call(&path, None, CommandRequest::Default { language }));
        let context = ready(&path, None, &context.id, 1);
        execute(
            &path,
            None,
            &context,
            if language == Language::Typescript {
                "let value: number=40;"
            } else {
                "let value=40;"
            },
        );
        assert_eq!(
            result(&execute(
                &path,
                None,
                &context,
                "await Promise.resolve(value+2)"
            )),
            "42"
        );
        let rich = execute(
            &path,
            None,
            &context,
            "display({'text/html':'<b>offline</b>'});console.log('stdio');value+3",
        );
        assert_eq!(result(&rich), "43");
        assert_eq!(output(&rich), b"stdio\n");
        let bad = execute(
            &path,
            None,
            &context,
            "await Promise.reject(new Error('expected-error'))",
        );
        assert!(
            bad.events
                .iter()
                .any(|e| matches!(&e.event,Event::Error {value,..} if value=="expected-error"))
        );
        for source in [
            "console.log('RUNNING');while(true){}",
            "console.log('RUNNING');await new Promise(()=>{})",
            "console.log('RUNNING');new Promise(()=>{})",
        ] {
            let execution = submit(&path, None, &context, source);
            entered(&path, None, &execution);
            call(
                &path,
                None,
                CommandRequest::Cancel {
                    context_id: context.id.clone(),
                    generation: context.generation,
                    execution_id: execution.clone(),
                },
            );
            assert_eq!(
                finished(&path, None, &execution).status,
                ExecutionStatus::Cancelled
            );
            assert_eq!(result(&execute(&path, None, &context, "value+2")), "42");
        }
        println!(
            "PASS code-service-{}-persistent-async-rich-errors-and-three-cancel-modes",
            language.name()
        );
        nodes.push(context);
    }
    for source in [
        "print('RUNNING')\nwhile True:\n    pass",
        "import asyncio\nprint('RUNNING')\nawait asyncio.sleep(30)",
    ] {
        let execution = submit(&path, None, &python, source);
        entered(&path, None, &execution);
        let unrelated = id();
        call(
            &path,
            None,
            CommandRequest::Cancel {
                context_id: python.id.clone(),
                generation: python.generation,
                execution_id: unrelated.clone(),
            },
        );
        assert_eq!(
            page(&path, None, &unrelated, 0).status,
            ExecutionStatus::Cancelled
        );
        assert_eq!(
            page(&path, None, &execution, 0).status,
            ExecutionStatus::Running
        );
        assert_eq!(result(&execute(&path, None, &nodes[0], "value+2")), "42");
        assert!(
            matches!(call(&path,None,CommandRequest::List {}),Response::Contexts(ref contexts) if contexts.len()==3)
        );
        call(
            &path,
            None,
            CommandRequest::Cancel {
                context_id: python.id.clone(),
                generation: python.generation,
                execution_id: execution.clone(),
            },
        );
        assert_eq!(
            finished(&path, None, &execution).status,
            ExecutionStatus::Cancelled
        );
        assert_eq!(result(&execute(&path, None, &python, "answer+2")), "42");
    }
    println!("PASS code-service-python-cpu-await-cancel-and-parallel-context-control");

    fs::create_dir("/workspace/custom").unwrap();
    let custom = context(call(
        &path,
        None,
        CommandRequest::Create {
            context_id: id(),
            language: Language::Python,
            cwd: "/workspace/custom".into(),
        },
    ));
    let custom = ready(&path, None, &custom.id, 1);
    let eid = id();
    call(
        &path,
        None,
        CommandRequest::Execute {
            context_id: custom.id.clone(),
            generation: custom.generation,
            execution_id: eid.clone(),
            code: "import os\n(os.getcwd(),os.environ.get('CELL_ONLY'))".into(),
            environment: BTreeMap::from([("CELL_ONLY".into(), "temporary".into())]),
            timeout_ms: 60000,
        },
    );
    assert_eq!(
        result(&finished(&path, None, &eid)),
        "('/workspace/custom', 'temporary')"
    );
    assert_eq!(
        result(&execute(
            &path,
            None,
            &custom,
            "os.environ.get('CELL_ONLY','absent')"
        )),
        "'absent'"
    );
    assert_eq!(
        exchange(
            &path,
            &envelope(
                None,
                CommandRequest::Create {
                    context_id: id(),
                    language: Language::Python,
                    cwd: "/workspace".into()
                }
            )
        )
        .error
        .unwrap()
        .code,
        "quota"
    );
    let timed = id();
    call(
        &path,
        None,
        CommandRequest::Execute {
            context_id: custom.id.clone(),
            generation: 1,
            execution_id: timed.clone(),
            code: "import asyncio\nawait asyncio.sleep(30)".into(),
            environment: BTreeMap::new(),
            timeout_ms: 250,
        },
    );
    assert_eq!(
        finished(&path, None, &timed).status,
        ExecutionStatus::TimedOut
    );
    println!("PASS code-service-create-cwd-env-four-context-quota-and-timeout");

    let lost = id();
    let request = envelope(
        None,
        CommandRequest::Execute {
            context_id: python.id.clone(),
            generation: 1,
            execution_id: lost.clone(),
            code: "answer+=1\nawait asyncio.sleep(.05)\nanswer".into(),
            environment: BTreeMap::new(),
            timeout_ms: 60000,
        },
    );
    let mut connection = UnixStream::connect(&path).unwrap();
    writeln!(connection, "{}", serde_json::to_string(&request).unwrap()).unwrap();
    drop(connection);
    wait(
        || {
            exchange(
                &path,
                &envelope(
                    None,
                    CommandRequest::Execution {
                        execution_id: lost.clone(),
                        after: 0,
                    },
                ),
            )
            .response
            .is_some()
        },
        10,
    );
    assert_eq!(result(&finished(&path, None, &lost)), "41");
    assert_eq!(exchange(&path, &request).error.unwrap().code, "conflict");
    assert_eq!(result(&execute(&path, None, &python, "answer")), "41");
    println!("PASS code-service-submit-disconnect-reconnect-journal-and-no-replay");

    let busy = submit(
        &path,
        None,
        &python,
        "import subprocess,sys\nchild=subprocess.Popen([sys.executable,'-c','import time;time.sleep(300)'],start_new_session=True)\nwith open('/workspace/restart-child','w') as marker:\n    marker.write(str(child.pid))\nprint('RUNNING')\nwhile True:\n    pass",
    );
    entered(&path, None, &busy);
    let old = python.clone();
    let child: u32 = fs::read_to_string("/workspace/restart-child")
        .unwrap()
        .parse()
        .unwrap();
    call(
        &path,
        None,
        CommandRequest::Restart {
            context_id: python.id.clone(),
            generation: 1,
        },
    );
    python = ready(&path, None, &python.id, 2);
    assert!(!Path::new(&format!("/proc/{}", old.pid.unwrap())).exists());
    assert!(!Path::new(&format!("/proc/{child}")).exists());
    assert_eq!(
        finished(&path, None, &busy).status,
        ExecutionStatus::Cancelled
    );
    assert_eq!(
        exchange(
            &path,
            &envelope(
                None,
                CommandRequest::Execute {
                    context_id: old.id,
                    generation: 1,
                    execution_id: id(),
                    code: "42".into(),
                    environment: BTreeMap::new(),
                    timeout_ms: 60000
                }
            )
        )
        .error
        .unwrap()
        .code,
        "stale_context"
    );
    assert_eq!(result(&execute(&path, None, &nodes[1], "value+2")), "42");
    assert_eq!(result(&execute(&path, None, &python, "6*7")), "42");
    let busy = submit(
        &path,
        None,
        &custom,
        "print('RUNNING')\nawait asyncio.sleep(30)",
    );
    entered(&path, None, &busy);
    call(
        &path,
        None,
        CommandRequest::Remove {
            context_id: custom.id.clone(),
            generation: 1,
        },
    );
    wait(
        || {
            exchange(
                &path,
                &envelope(
                    None,
                    CommandRequest::Info {
                        context_id: custom.id.clone(),
                    },
                ),
            )
            .error
            .is_some_and(|e| e.code == "not_found")
        },
        10,
    );
    assert_eq!(
        finished(&path, None, &busy).status,
        ExecutionStatus::Cancelled
    );
    println!("PASS code-service-busy-restart-remove-generation-and-other-context-state");

    let blockers: Vec<_> = (0..4)
        .map(|_| UnixStream::connect(&path).unwrap())
        .collect();
    wait(|| service.active_connections() == 4, 10);
    let pids = [
        python.pid.unwrap(),
        nodes[0].pid.unwrap(),
        nodes[1].pid.unwrap(),
    ];
    drop(service);
    drop(blockers);
    drop(watch);
    zero_groups();
    for pid in pids {
        assert!(!Path::new(&format!("/proc/{pid}")).exists());
    }
    println!("PASS code-service-close-with-partial-controls-joins-all-interpreters-and-workers");

    for entry in fs::read_dir("/workspace").unwrap() {
        let entry = entry.unwrap();
        if entry.file_type().unwrap().is_dir() {
            fs::remove_dir_all(entry.path()).unwrap();
        } else {
            fs::remove_file(entry.path()).unwrap();
        }
    }
    let (service, path) = start();
    let binding = pristine::Binding {
        session_id: "a".repeat(24),
        nonce: "d".repeat(64),
    };
    let prepare = serde_json::json!({"protocol":pristine::PROTOCOL,"job_id":id(),"operation":"prepare","prepare":{"binding":binding,"mode":"session","ttl_ms":12000,"network":"none","input_files":[{"path":"seed","data":STANDARD.encode(b"offline"),"mode":292}]}});
    let (runtime, _, _) = main_rpc(
        pristine::Runtime::Pristine,
        service.clone(),
        None,
        prepare,
        |reply| {
            assert_eq!(reply["ok"], true, "{reply}");
            assert_eq!(reply["binding"], serde_json::to_value(&binding).unwrap());
            let warm = context(call(
                &path,
                Some(&binding),
                CommandRequest::Default {
                    language: Language::Python,
                },
            ));
            assert_eq!(warm.id, service.prewarmed_context().unwrap().id);
        },
    );
    assert!(matches!(
        runtime,
        pristine::Runtime::Prepared {
            one_shot: false,
            ..
        }
    ));
    let mut wrong = binding.clone();
    wrong.nonce = "e".repeat(64);
    assert_eq!(
        exchange(&path, &envelope(Some(&wrong), CommandRequest::List {}))
            .error
            .unwrap()
            .code,
        "invalid_binding"
    );
    assert_eq!(
        exchange(&path, &envelope(None, CommandRequest::List {}))
            .error
            .unwrap()
            .code,
        "invalid_binding"
    );
    let python = service.prewarmed_context().unwrap().clone();
    assert_eq!(
        result(&execute(
            &path,
            Some(&binding),
            &python,
            "open('/input/seed').read()"
        )),
        "'offline'"
    );
    let busy = submit(
        &path,
        Some(&binding),
        &python,
        "print('RUNNING')\nwhile True:\n    pass",
    );
    entered(&path, Some(&binding), &busy);
    // No main RPC, revoke or Drop is allowed to initiate this expiry cleanup.
    zero_groups();
    assert!(!Path::new(&format!("/proc/{}", python.pid.unwrap())).exists());
    drop(service);
    println!("PASS code-service-prepare-ack-binding-readonly-input-and-independent-lease-cleanup");

    reset_input();
    let (service, _path) = start();
    let prepare = serde_json::json!({"protocol":pristine::PROTOCOL,"job_id":id(),"operation":"prepare","prepare":{"binding":binding,"mode":"job","ttl_ms":10000,"network":"none"}});
    let (_, _, reply) = main_rpc(
        pristine::Runtime::Pristine,
        service.clone(),
        None,
        prepare,
        |reply| {
            assert_eq!(reply["ok"], true);
            assert!(reply.get("code_service").is_none());
        },
    );
    assert!(reply["ok"].as_bool().unwrap());
    zero_groups();
    drop(service);
    println!("PASS code-service-one-shot-prepare-revokes-prewarm-before-ack");

    reset_input();
    let (service, path) = start();
    let prepare = serde_json::json!({"protocol":pristine::PROTOCOL,"job_id":id(),"operation":"prepare","prepare":{"binding":binding,"mode":"session","ttl_ms":60000,"network":"none"}});
    let (runtime, _, _) = main_rpc(
        pristine::Runtime::Pristine,
        service.clone(),
        None,
        prepare,
        |reply| assert_eq!(reply["ok"], true),
    );
    let mut bad = ping(pristine::PROTOCOL);
    bad["binding"] = serde_json::to_value(wrong).unwrap();
    let (runtime, action, _) = main_rpc(runtime, service.clone(), None, bad, |reply| {
        assert_eq!(reply["ok"], false)
    });
    assert_eq!(action, ConnectionAction::Poweroff);
    assert!(matches!(runtime, pristine::Runtime::Poisoned));
    zero_groups();
    drop(service);
    let _ = path;
    println!("PASS code-service-poisoned-main-request-revokes-and-reaps-contexts");
    let (service, _path) = start();
    let (_, action, reply) = main_rpc(
        pristine::Runtime::Legacy,
        service.clone(),
        None,
        serde_json::json!({"protocol":PROTOCOL,"job_id":id(),"argv":["/bin/bash","-c","printf legacy-job"],"timeout_ms":5000,"max_output_bytes":4096}),
        |reply| {
            assert_eq!(reply["ok"], true);
            assert!(reply.get("code_service").is_none());
        },
    );
    assert_eq!(action, ConnectionAction::Poweroff);
    assert_eq!(reply["stdout"], "legacy-job");
    zero_groups();
    drop(service);
    println!("PASS code-service-legacy-one-shot-revokes-code-without-killing-command");
    println!("RUST_CODE_SERVICE_PASS");
    poweroff();
}

#[test]
fn code_boot_policy_is_explicit_and_selects_a_supported_prewarm() {
    use firecracker_linux_agent::code_context::Language;
    assert_eq!(
        code_prewarm_policy("console=ttyS0 agent.pristine=1").unwrap(),
        None
    );
    assert_eq!(
        code_prewarm_policy("agent.code=5003").unwrap(),
        Some(Language::Python)
    );
    assert_eq!(
        code_prewarm_policy("agent.code=5003 agent.code-prewarm=typescript").unwrap(),
        Some(Language::Typescript)
    );
    for line in [
        "agent.code=5004",
        "agent.code-prewarm=python",
        "agent.code=5003 agent.code-prewarm=ruby",
        "agent.code=5003 agent.code=5003",
        "agent.code=5003 agent.code-prewarm=python agent.code-prewarm=javascript",
    ] {
        assert!(code_prewarm_policy(line).is_err(), "{line}");
    }
}
