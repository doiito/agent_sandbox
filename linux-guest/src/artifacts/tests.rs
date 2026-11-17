use super::{service::Service, tree::Snapshot, *};
use crate::pristine::{Binding, Runtime};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
use std::os::unix::{
    ffi::OsStringExt,
    fs::FileExt,
    net::{UnixListener, UnixStream},
};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Tree(PathBuf);
impl Tree {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "osv-artifacts-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        Self(path)
    }
    fn capture(&self, path: &str) -> Result<Snapshot> {
        Snapshot::capture(&self.0, path, &mut || Ok(()))
    }
}
impl Drop for Tree {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn snapshot_large_binary_unicode_empty_and_bytewise_order() {
    let tree = Tree::new();
    fs::create_dir(tree.0.join("a")).unwrap();
    fs::create_dir(tree.0.join("empty")).unwrap();
    fs::write(tree.0.join("a-"), []).unwrap();
    let data = [0u8, 255, 128, 13, 10].repeat(150001);
    fs::write(tree.0.join("a/报告"), &data).unwrap();
    let snapshot = tree.capture("/workspace").unwrap();
    assert_eq!(
        snapshot
            .entries()
            .map(|e| e.path.as_str())
            .collect::<Vec<_>>(),
        ["a", "a-", "a/报告", "empty"]
    );
    assert_eq!(
        (snapshot.count(), snapshot.files(), snapshot.payload_bytes()),
        (4, 2, data.len() as u64)
    );
    let mut output = Vec::new();
    let mut chunks = 0;
    snapshot
        .read_file(
            snapshot.entries().find(|e| e.path == "a/报告").unwrap(),
            &mut || Ok(()),
            |offset, bytes| {
                assert_eq!(offset, output.len() as u64);
                assert!(bytes.len() <= DATA_BYTES);
                chunks += 1;
                output.extend_from_slice(bytes);
                Ok(())
            },
        )
        .unwrap();
    assert!(chunks > 8);
    assert_eq!(output, data);
    snapshot.verify(&mut || Ok(())).unwrap();
    let single = tree.capture("/workspace/a/报告").unwrap();
    assert_eq!(single.kind(), "file");
    assert_eq!(single.entries().next().unwrap().path, "报告");
    let empty = tree.capture("/workspace/empty").unwrap();
    assert_eq!((empty.kind(), empty.count()), ("directory", 0));
}

#[test]
fn snapshot_detects_read_and_tree_mutations() {
    let tree = Tree::new();
    let path = tree.0.join("file");
    fs::write(&path, vec![42; DATA_BYTES * 3]).unwrap();
    let snapshot = tree.capture("/workspace").unwrap();
    let entry = snapshot.entries().next().unwrap();
    let result = snapshot.read_file(entry, &mut || Ok(()), |offset, _| {
        if offset == 0 {
            File::options()
                .write(true)
                .open(&path)
                .unwrap()
                .set_len(entry.size + 1)
                .unwrap();
        }
        Ok(())
    });
    assert_eq!(result, Err("conflict"));
    assert_eq!(snapshot.verify(&mut || Ok(())), Err("conflict"));
    let snapshot = tree.capture("/workspace").unwrap();
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .write_at(&[99], 0)
        .unwrap();
    assert_eq!(snapshot.verify(&mut || Ok(())), Err("conflict"));
    let snapshot = tree.capture("/workspace").unwrap();
    fs::create_dir(tree.0.join("new-empty")).unwrap();
    assert_eq!(snapshot.verify(&mut || Ok(())), Err("conflict"));
    let snapshot = tree.capture("/workspace/file").unwrap();
    fs::rename(&path, tree.0.join("old")).unwrap();
    fs::write(&path, vec![42; DATA_BYTES * 3 + 1]).unwrap();
    let entry = snapshot.entries().next().unwrap();
    assert_eq!(
        snapshot.read_file(entry, &mut || Ok(()), |_, _| Ok(())),
        Err("conflict")
    );
}

#[test]
fn snapshot_rejects_links_fifo_and_unsafe_names_without_opening_them() {
    for kind in [
        "symlink", "hardlink", "fifo", "reserved", "drive", "newline", "non-utf8",
    ] {
        let tree = Tree::new();
        match kind {
            "symlink" => std::os::unix::fs::symlink("/etc/passwd", tree.0.join("unsafe")).unwrap(),
            "hardlink" => {
                fs::write(tree.0.join("file"), b"a").unwrap();
                fs::hard_link(tree.0.join("file"), tree.0.join("unsafe")).unwrap();
            }
            "fifo" => {
                let path =
                    CString::new(tree.0.join("unsafe").as_os_str().as_encoded_bytes()).unwrap();
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
            "reserved" => fs::write(tree.0.join(MANIFEST), []).unwrap(),
            "drive" => {
                fs::create_dir(tree.0.join("C:")).unwrap();
            }
            "newline" => fs::write(tree.0.join("bad\nname"), []).unwrap(),
            "non-utf8" => {
                fs::write(tree.0.join(std::ffi::OsString::from_vec(vec![255])), []).unwrap()
            }
            _ => unreachable!(),
        }
        assert!(tree.capture("/workspace").is_err(), "accepted {kind}");
    }
    let tree = Tree::new();
    for path in [
        "/",
        "/workspace/../etc",
        "/workspace/",
        "/workspace//x",
        "/workspace/x\\y",
        "/workspace/x\0",
    ] {
        assert!(tree.capture(path).is_err(), "accepted {path}");
    }
}

#[test]
fn snapshot_enforces_entry_path_depth_and_payload_limits() {
    let tree = Tree::new();
    File::create(tree.0.join("huge"))
        .unwrap()
        .set_len(MAX_BYTES + 1)
        .unwrap();
    assert_eq!(tree.capture("/workspace").err(), Some("too_large"));
    fs::remove_file(tree.0.join("huge")).unwrap();
    for index in 0..MAX_ENTRIES + 1 {
        fs::write(tree.0.join(format!("f{index:04}")), []).unwrap();
    }
    assert_eq!(tree.capture("/workspace").err(), Some("too_large"));
    let tree = Tree::new();
    for index in 0..400 {
        fs::write(tree.0.join(format!("{index:04}{}", "a".repeat(200))), []).unwrap();
    }
    assert_eq!(tree.capture("/workspace").err(), Some("too_large"));
    let tree = Tree::new();
    let mut path = tree.0.clone();
    for _ in 0..MAX_DEPTH + 1 {
        path = path.join("dir");
        fs::create_dir(&path).unwrap();
    }
    assert!(tree.capture("/workspace").is_err());
    assert_eq!(
        Snapshot::capture(&tree.0, "/workspace", &mut || Err("expired")).err(),
        Some("expired")
    );
}

fn accept(raw: RawFd, deadline: Instant) -> io::Result<Option<File>> {
    let mut item = libc::pollfd {
        fd: raw,
        events: libc::POLLIN,
        revents: 0,
    };
    let count = unsafe {
        libc::poll(
            &mut item,
            1,
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis() as i32,
        )
    };
    if count <= 0 {
        return Ok(None);
    }
    let fd = unsafe {
        libc::accept4(
            raw,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC,
        )
    };
    if fd < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(Some(unsafe { File::from_raw_fd(fd) }))
    }
}
fn binding() -> Binding {
    Binding {
        session_id: "0123456789abcdef01234567".into(),
        nonce: "d".repeat(64),
    }
}
fn request(binding: Option<&Binding>) -> Value {
    json!({"protocol":"fc-artifact/v1","session_id":"0123456789abcdef01234567","artifact_id":"abcdef0123456789abcdef01",
        "nonce":"c".repeat(64),"path":"/workspace","binding":binding})
}
fn call(path: &std::path::Path, request: &Value) -> Vec<Value> {
    let mut stream = UnixStream::connect(path).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(format!("{request}\n").as_bytes()).unwrap();
    let mut output = String::new();
    stream.read_to_string(&mut output).unwrap();
    output
        .lines()
        .enumerate()
        .map(|(index, line)| {
            assert!(line.len() < 128 << 10);
            let frame: Value =
                serde_json::from_str(line.strip_prefix("FC_ARTIFACT_EVENT ").unwrap()).unwrap();
            assert_eq!(frame["sequence"], index);
            for key in ["protocol", "session_id", "artifact_id", "nonce"] {
                assert_eq!(frame[key], request[key]);
            }
            assert_eq!(
                frame.get("binding").unwrap_or(&Value::Null),
                &request["binding"]
            );
            frame
        })
        .collect()
}

#[test]
fn service_enforces_authorization_binding_and_full_transfer() {
    let workspace = Tree::new();
    let socket = Tree::new();
    let path = socket.0.join("service.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let listener = unsafe { File::from_raw_fd(listener.into_raw_fd()) };
    let hard = Instant::now() + Duration::from_secs(15);
    let service =
        Service::with_listener(&workspace.0, &Runtime::Pristine, hard, listener, accept).unwrap();
    assert_eq!(call(&path, &request(None))[0]["code"], "unsupported");
    let bind = binding();
    let runtime = Runtime::Prepared {
        binding: bind.clone(),
        deadline: hard,
        one_shot: false,
    };
    service.update(&runtime, hard);
    let data = [0u8, 255, 1].repeat(250001);
    fs::write(workspace.0.join("large"), &data).unwrap();
    let frames = call(&path, &request(Some(&bind)));
    assert_eq!(frames[0]["kind"], "ready");
    let mut output = Vec::new();
    for frame in &frames {
        if frame["kind"] == "data" {
            assert_eq!(frame["offset"], output.len());
            output.extend_from_slice(
                &STANDARD
                    .decode(frame["data_base64"].as_str().unwrap())
                    .unwrap(),
            );
        }
    }
    assert_eq!(output, data);
    assert_eq!(
        frames.last().unwrap()["totals"]["payload_bytes"],
        data.len()
    );
    let mut wrong = bind.clone();
    wrong.nonce = "f".repeat(64);
    assert_eq!(
        call(&path, &request(Some(&wrong)))[0]["code"],
        "invalid_binding"
    );
    service.update(
        &Runtime::Prepared {
            binding: bind.clone(),
            deadline: hard,
            one_shot: true,
        },
        hard,
    );
    assert_eq!(call(&path, &request(Some(&bind)))[0]["code"], "unsupported");
    service.update(&Runtime::Legacy, hard);
    assert_eq!(call(&path, &request(None))[0]["code"], "unsupported");
    service.authorize_legacy_session(hard);
    assert_eq!(call(&path, &request(None))[0]["kind"], "ready");
    service.revoke();
    assert_eq!(call(&path, &request(None))[0]["code"], "unsupported");
    drop(service);
}

#[test]
fn service_drop_unblocks_stalled_request_and_reclaims_its_thread() {
    let workspace = Tree::new();
    let socket = Tree::new();
    let path = socket.0.join("service.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let listener = unsafe { File::from_raw_fd(listener.into_raw_fd()) };
    let service = Service::with_listener(
        &workspace.0,
        &Runtime::Legacy,
        Instant::now() + Duration::from_secs(15),
        listener,
        accept,
    )
    .unwrap();
    let mut client = UnixStream::connect(&path).unwrap();
    client.write_all(b"{").unwrap();
    std::thread::sleep(Duration::from_millis(20));
    let start = Instant::now();
    drop(service);
    assert!(start.elapsed() < Duration::from_secs(1));
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut byte = [0];
    assert!(matches!(client.read(&mut byte), Ok(0) | Err(_)));
}

#[test]
fn main_control_updates_authorization_before_reply_and_revokes_poisoned_owner() {
    use std::io::{BufRead, BufReader};
    let workspace = Tree::new();
    let socket = Tree::new();
    let path = socket.0.join("service.sock");
    let listener = UnixListener::bind(&path).unwrap();
    let listener = unsafe { File::from_raw_fd(listener.into_raw_fd()) };
    let hard = Instant::now() + Duration::from_secs(15);
    let service =
        Service::with_listener(&workspace.0, &Runtime::Pristine, hard, listener, accept).unwrap();
    let bind = binding();
    let mut runtime = Runtime::Prepared {
        binding: bind.clone(),
        deadline: hard,
        one_shot: false,
    };
    assert_eq!(call(&path, &request(Some(&bind)))[0]["code"], "unsupported");
    let (mut client, server) = UnixStream::pair().unwrap();
    writeln!(client,"{}",json!({"protocol":crate::pristine::PROTOCOL,"job_id":"e".repeat(24),"operation":"ping","binding":bind})).unwrap();
    assert_eq!(
        crate::handle_connection_artifacts(
            unsafe { File::from_raw_fd(server.into_raw_fd()) },
            None,
            hard,
            &mut runtime,
            crate::ConnectionServices { artifacts: Some(&service), ..Default::default() }
        ),
        crate::ConnectionAction::Continue
    );
    let mut reply = String::new();
    BufReader::new(client).read_line(&mut reply).unwrap();
    let reply: Value =
        serde_json::from_str(reply.strip_prefix(crate::RESULT_PREFIX).unwrap()).unwrap();
    assert_eq!(reply["ok"], true);
    assert_eq!(call(&path, &request(Some(&bind)))[0]["kind"], "ready");
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(b"{bad json}\n").unwrap();
    assert_eq!(
        crate::handle_connection_artifacts(
            unsafe { File::from_raw_fd(server.into_raw_fd()) },
            None,
            hard,
            &mut runtime,
            crate::ConnectionServices { artifacts: Some(&service), ..Default::default() }
        ),
        crate::ConnectionAction::Poweroff
    );
    assert_eq!(call(&path, &request(Some(&bind)))[0]["code"], "unsupported");
}

#[test]
fn boot_policy_requires_one_explicit_correct_port_and_successful_initialization() {
    assert_eq!(crate::artifact_policy("quiet"), Ok(false));
    assert_eq!(
        crate::artifact_policy("quiet agent.artifacts=5005"),
        Ok(true)
    );
    for value in [
        "agent.artifacts=5004",
        "agent.artifacts=",
        "agent.artifacts=5005 agent.artifacts=5005",
    ] {
        assert!(crate::artifact_policy(value).is_err());
    }
    assert!(
        crate::start_artifact_service(
            "agent.artifacts=5005",
            Some("fixture initialization failure"),
            &Runtime::Legacy,
            Instant::now() + Duration::from_secs(5)
        )
        .is_err()
    );
}

#[test]
#[ignore = "requires private VM mounts; run by qemu-artifact-init"]
fn actual_vm_prepare_ack_one_shot_cross_filesystem_and_shutdown() {
    use std::io::{BufRead, BufReader};
    assert_eq!(std::env::var("OSV_ARTIFACT_VM").as_deref(), Ok("1"));
    fn main_rpc(
        service: &Service,
        runtime: &mut Runtime,
        hard: Instant,
        request: Value,
    ) -> (crate::ConnectionAction, Value) {
        let (mut client, server) = UnixStream::pair().unwrap();
        writeln!(client, "{request}").unwrap();
        let action = crate::handle_connection_artifacts(
            unsafe { File::from_raw_fd(server.into_raw_fd()) },
            None,
            hard,
            runtime,
            crate::ConnectionServices { artifacts: Some(service), ..Default::default() },
        );
        let mut line = String::new();
        BufReader::new(client).read_line(&mut line).unwrap();
        (
            action,
            serde_json::from_str(line.strip_prefix(crate::RESULT_PREFIX).unwrap()).unwrap(),
        )
    }
    for mode in ["session", "job"] {
        for path in ["/input", "/workspace"] {
            fs::create_dir_all(path).unwrap();
            crate::mount_required(
                "tmpfs",
                path,
                "tmpfs",
                libc::MS_NODEV | libc::MS_NOSUID,
                Some("size=4m,mode=0755"),
            )
            .unwrap();
        }
        let socket = Tree::new();
        let path = socket.0.join("service.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let listener = unsafe { File::from_raw_fd(listener.into_raw_fd()) };
        let hard = Instant::now() + Duration::from_secs(30);
        let mut runtime = Runtime::Pristine;
        let service = Service::with_listener(
            std::path::Path::new("/workspace"),
            &runtime,
            hard,
            listener,
            accept,
        )
        .unwrap();
        let bind = binding();
        assert_eq!(call(&path, &request(Some(&bind)))[0]["code"], "unsupported");
        let prepare = json!({"protocol":crate::pristine::PROTOCOL,"job_id":"a".repeat(24),"operation":"prepare",
            "prepare":{"binding":bind,"mode":mode,"ttl_ms":10000,"network":"none","input_files":[]}});
        let (action, reply) = main_rpc(&service, &mut runtime, hard, prepare);
        assert_eq!(action, crate::ConnectionAction::Continue);
        assert_eq!(reply["ok"], true, "{reply}");
        assert_eq!(reply["guest_state"], "prepared");
        fs::write("/workspace/result", b"actual prepared VM artifact\0\xff").unwrap();
        let frames = call(&path, &request(Some(&bind)));
        if mode == "session" {
            assert_eq!(frames[0]["kind"], "ready");
            assert_eq!(frames.last().unwrap()["totals"]["files"], 1);
            fs::create_dir("/workspace/cross").unwrap();
            crate::mount_required(
                "tmpfs",
                "/workspace/cross",
                "tmpfs",
                libc::MS_NODEV | libc::MS_NOSUID,
                Some("size=1m"),
            )
            .unwrap();
            assert_eq!(call(&path, &request(Some(&bind)))[0]["code"], "denied");
            let cross = CString::new("/workspace/cross").unwrap();
            assert_eq!(unsafe { libc::umount(cross.as_ptr()) }, 0);
        } else {
            assert_eq!(frames[0]["code"], "unsupported");
        }
        let (action, reply) = main_rpc(
            &service,
            &mut runtime,
            hard,
            json!({"protocol":crate::pristine::PROTOCOL,"job_id":"b".repeat(24),"operation":"shutdown","binding":bind}),
        );
        assert_eq!(action, crate::ConnectionAction::Poweroff);
        assert_eq!(reply["ok"], true);
        assert_eq!(call(&path, &request(Some(&bind)))[0]["code"], "unsupported");
        drop(service);
        for path in ["/workspace", "/input"] {
            let path = CString::new(path).unwrap();
            assert_eq!(unsafe { libc::umount(path.as_ptr()) }, 0);
        }
    }
}
