use super::*;
use std::collections::BTreeSet;

pub(crate) const PROTOCOL: &str = "fc-agent/v3";

#[derive(Default)]
pub(crate) struct RequestBudget {
    tenant: usize,
    pristine_checks: usize,
}

impl RequestBudget {
    pub fn permits(&self) -> bool {
        self.tenant < SESSION_MAX_REQUESTS && self.pristine_checks < 6000
    }
    pub fn record(&mut self, was_pristine: bool, runtime: &Runtime) {
        if was_pristine && runtime.is_pristine() {
            self.pristine_checks += 1;
        } else {
            self.tenant += 1;
        }
    }
}

pub(crate) use firecracker_linux_agent::code_service::Binding;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PrepareRequest {
    #[serde(default)]
    network: String,
    binding: Binding,
    mode: String,
    ttl_ms: u64,
    #[serde(default)]
    input_files: Vec<PrepareInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PrepareInput {
    path: String,
    data: String,
    #[serde(default)]
    mode: u32,
}

pub(crate) enum Runtime {
    Legacy,
    Pristine,
    Prepared {
        binding: Binding,
        deadline: Instant,
        one_shot: bool,
    },
    Poisoned,
}

impl Runtime {
    pub fn is_pristine(&self) -> bool {
        matches!(self, Self::Pristine)
    }
    pub fn accept_deadline(&self, boot_deadline: Instant) -> Instant {
        match self {
            Self::Prepared { deadline, .. } => (*deadline).min(boot_deadline),
            _ => boot_deadline,
        }
    }
    pub fn enabled(&self) -> bool {
        !matches!(self, Self::Legacy)
    }

    pub fn invalid_frame(&mut self) -> ConnectionAction {
        if !self.enabled() {
            return ConnectionAction::Continue;
        }
        *self = Self::Poisoned;
        ConnectionAction::Poweroff
    }

    fn reject(&mut self, id: &str, message: &str) -> (JobResult, ConnectionAction) {
        *self = Self::Poisoned;
        (
            error_result(id, PROTOCOL, message.into()),
            ConnectionAction::Poweroff,
        )
    }

    #[cfg(test)]
    pub fn dispatch(
        &mut self,
        request: JobRequest,
        init_error: Option<&str>,
        boot_deadline: Instant,
        input_root: &Path,
        workspace: &Path,
        freeze: fn(&Path) -> io::Result<()>,
    ) -> (JobResult, ConnectionAction) {
        self.dispatch_stream(
            request,
            init_error,
            boot_deadline,
            input_root,
            workspace,
            freeze,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn dispatch_stream(
        &mut self,
        mut request: JobRequest,
        init_error: Option<&str>,
        boot_deadline: Instant,
        input_root: &Path,
        workspace: &Path,
        freeze: fn(&Path) -> io::Result<()>,
        stream: Option<super::streaming::StreamWriter>,
    ) -> (JobResult, ConnectionAction) {
        if init_error.is_some() {
            return self.reject(&request.job_id, "pristine guest initialization failed");
        }
        if request.protocol != PROTOCOL
            || validate_request(&request).is_err()
            || !hex_id(&request.job_id, 24)
        {
            return self.reject(&request.job_id, "invalid pristine protocol request");
        }
        if Instant::now() >= boot_deadline {
            return self.reject(&request.job_id, "guest lifetime expired");
        }
        if matches!(self, Self::Pristine) {
            match request.operation.as_deref() {
                Some("ping") if request.binding.is_none() && request.prepare.is_none() => {
                    let mut result = success_result(&request.job_id, PROTOCOL);
                    result.guest_state = Some("pristine");
                    result.pristine_revision = Some(2);
                    result.remaining_lifetime_ms = Some(
                        boot_deadline
                            .saturating_duration_since(Instant::now())
                            .as_millis() as u64,
                    );
                    return (result, ConnectionAction::Continue);
                }
                Some("shutdown") if request.binding.is_none() && request.prepare.is_none() => {
                    *self = Self::Poisoned;
                    return (
                        success_result(&request.job_id, PROTOCOL),
                        ConnectionAction::Poweroff,
                    );
                }
                Some("prepare") => {
                    // A failed or interrupted preparation can never become pristine again.
                    *self = Self::Poisoned;
                    let Some(prepare) = request.prepare.as_ref() else {
                        return self.reject(&request.job_id, "preparation missing");
                    };
                    let files = match validate_prepare(prepare, boot_deadline) {
                        Ok(files) => files,
                        Err(error) => return self.reject(&request.job_id, &error),
                    };
                    if let Err(error) =
                        stage_input(input_root, workspace, &files).and_then(|()| freeze(input_root))
                    {
                        return self
                            .reject(&request.job_id, &format!("preparation failed: {error}"));
                    }
                    let now = Instant::now();
                    let deadline = now + Duration::from_millis(prepare.ttl_ms);
                    if deadline + Duration::from_secs(5) > boot_deadline {
                        return self
                            .reject(&request.job_id, "preparation exceeds remaining lifetime");
                    }
                    let binding = prepare.binding.clone();
                    if prepare.network == "proxy"
                        && let Err(error) = network_proxy::enable()
                    {
                        return self.reject(
                            &request.job_id,
                            &format!("proxy initialization failed: {error}"),
                        );
                    }
                    *self = Self::Prepared {
                        binding: binding.clone(),
                        deadline,
                        one_shot: prepare.mode == "job",
                    };
                    let mut result = success_result(&request.job_id, PROTOCOL);
                    result.binding = Some(binding);
                    result.guest_state = Some("prepared");
                    result.pristine_revision = Some(2);
                    result.remaining_lifetime_ms = Some(prepare.ttl_ms);
                    return (result, ConnectionAction::Continue);
                }
                _ => {
                    return self.reject(&request.job_id, "guest must be prepared before execution");
                }
            }
        }
        let (binding, deadline, one_shot) = match self {
            Self::Prepared {
                binding,
                deadline,
                one_shot,
            } => (binding.clone(), *deadline, *one_shot),
            _ => return self.reject(&request.job_id, "guest is not usable"),
        };
        if request.binding.as_ref() != Some(&binding) || request.prepare.is_some() {
            return self.reject(
                &request.job_id,
                "prepared guest binding mismatch or repeated preparation",
            );
        }
        if Instant::now() >= deadline {
            return self.reject(&request.job_id, "prepared lease expired");
        }
        let action = match request.operation.as_deref() {
            Some("shutdown") => ConnectionAction::Poweroff,
            Some("run") if one_shot => ConnectionAction::Poweroff,
            Some("run_stream") if one_shot => {
                return self.reject(
                    &request.job_id,
                    "one-shot guest does not accept streamed session commands",
                );
            }
            Some("file") if one_shot => {
                return self.reject(
                    &request.job_id,
                    "one-shot guest does not accept file operations",
                );
            }
            Some("ping" | "run" | "run_stream" | "file") => ConnectionAction::Continue,
            _ => return self.reject(&request.job_id, "unsupported prepared operation"),
        };
        let mut result = match request.operation.as_deref() {
            Some("ping" | "shutdown") => success_result(&request.job_id, PROTOCOL),
            Some("file") => run_file(&request, workspace),
            _ => {
                request.timeout_ms = request.timeout_ms.min(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis()
                        .max(1) as u64,
                );
                if request.operation.as_deref() == Some("run_stream") {
                    super::run_job_stream(request, stream)
                } else {
                    run_job(request)
                }
            }
        };
        result.protocol = PROTOCOL;
        result.binding = Some(binding);
        result.guest_state = Some("prepared");
        result.pristine_revision = Some(2);
        result.remaining_lifetime_ms = Some(
            deadline
                .saturating_duration_since(Instant::now())
                .as_millis() as u64,
        );
        if action == ConnectionAction::Poweroff {
            *self = Self::Poisoned;
        }
        (result, action)
    }
}

fn hex_id(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_input_path(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && !value.starts_with('/')
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
        && value.split('/').count() <= 16
        && value
            .split('/')
            .all(|part| !part.is_empty() && part != "." && part != ".." && part.len() <= 255)
}

fn validate_prepare(
    request: &PrepareRequest,
    boot_deadline: Instant,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    if !hex_id(&request.binding.session_id, 24)
        || !hex_id(&request.binding.nonce, 64)
        || !matches!(request.mode.as_str(), "job" | "session")
        || !matches!(request.network.as_str(), "" | "none" | "proxy")
        || !(1000..=if request.mode == "session" {
            600_000
        } else {
            300_000
        })
            .contains(&request.ttl_ms)
        || request.input_files.len() > 64
        || Instant::now() + Duration::from_millis(request.ttl_ms) + Duration::from_secs(5)
            > boot_deadline
    {
        return Err("invalid preparation binding, mode, lease or file count".into());
    }
    let mut paths = BTreeSet::new();
    let mut name_bytes = 0usize;
    let mut data_bytes = 0usize;
    let mut result = Vec::with_capacity(request.input_files.len());
    for input in &request.input_files {
        name_bytes = name_bytes.saturating_add(input.path.len());
        if !valid_input_path(&input.path)
            || !matches!(input.mode, 0 | 0o444)
            || name_bytes > 32 * 1024
            || !paths.insert(input.path.clone())
            || input.data.len() > (512 * 1024usize).div_ceil(3) * 4
        {
            return Err("invalid preparation input path, mode or size".into());
        }
        let data = STANDARD
            .decode(&input.data)
            .map_err(|_| "invalid preparation base64")?;
        data_bytes = data_bytes.saturating_add(data.len());
        if data_bytes > 512 * 1024 || STANDARD.encode(&data) != input.data {
            return Err("preparation input bytes exceed budget or noncanonical base64".into());
        }
        result.push((input.path.clone(), data));
    }
    for path in &paths {
        let mut prefix = String::new();
        for part in path.split('/').take(path.split('/').count() - 1) {
            if !prefix.is_empty() {
                prefix.push('/');
            }
            prefix.push_str(part);
            if paths.contains(&prefix) {
                return Err("preparation input file/directory conflict".into());
            }
        }
    }
    Ok(result)
}

fn open_directory(path: &Path) -> io::Result<File> {
    use std::os::unix::ffi::OsStrExt;
    let path = CString::new(path.as_os_str().as_bytes())?;
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(unsafe { File::from_raw_fd(fd) })
}

fn stage_input(root: &Path, workspace: &Path, files: &[(String, Vec<u8>)]) -> io::Result<()> {
    let directory = open_directory(root)?;
    let _workspace = open_directory(workspace)?;
    if fs::read_dir(root)?.next().is_some() || fs::read_dir(workspace)?.next().is_some() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "preparation requires empty input and workspace",
        ));
    }
    for (path, bytes) in files {
        let parts: Vec<_> = path.split('/').collect();
        let mut parent = directory.try_clone()?;
        for name in &parts[..parts.len() - 1] {
            let name_c = CString::new(*name)?;
            if unsafe { libc::mkdirat(parent.as_raw_fd(), name_c.as_ptr(), 0o700) } < 0
                && io::Error::last_os_error().raw_os_error() != Some(libc::EEXIST)
            {
                return Err(io::Error::last_os_error());
            }
            parent = open_beneath(
                parent.as_raw_fd(),
                name,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW,
                0,
            )?;
        }
        let mut target = open_beneath(
            parent.as_raw_fd(),
            parts[parts.len() - 1],
            libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW,
            0o600,
        )?;
        target.write_all(bytes)?;
        if unsafe { libc::fchmod(target.as_raw_fd(), 0o444) } < 0 {
            return Err(io::Error::last_os_error());
        }
        target.sync_all()?;
    }
    fn readonly_directories(path: &Path) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt;
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                readonly_directories(&entry.path())?;
            } else if !kind.is_file() {
                return Err(io::Error::from_raw_os_error(libc::EACCES));
            }
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o555))
    }
    readonly_directories(root)
}

pub(crate) fn freeze_input(path: &Path) -> io::Result<()> {
    use std::os::unix::ffi::OsStrExt;
    let path_c = CString::new(path.as_os_str().as_bytes())?;
    let flags =
        libc::MS_REMOUNT | libc::MS_RDONLY | libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC;
    if unsafe {
        libc::mount(
            std::ptr::null(),
            path_c.as_ptr(),
            std::ptr::null(),
            flags,
            std::ptr::null(),
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    let required = libc::ST_RDONLY | libc::ST_NOSUID | libc::ST_NODEV | libc::ST_NOEXEC;
    if unsafe { libc::statvfs(path_c.as_ptr(), &mut stat) } < 0
        || stat.f_flag & required != required
    {
        return Err(io::Error::other(
            "prepared input mount lacks required readonly/security flags",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pristine_health_checks_preserve_tenant_request_budget() {
        let mut budget = RequestBudget::default();
        let mut state = Runtime::Pristine;
        for _ in 0..500 {
            budget.record(true, &state);
        }
        assert!(budget.permits());
        state = Runtime::Prepared {
            binding: binding(),
            deadline: Instant::now() + Duration::from_secs(10),
            one_shot: false,
        };
        budget.record(true, &state);
        for _ in 0..SESSION_MAX_REQUESTS - 2 {
            budget.record(false, &state);
        }
        assert!(budget.permits());
        budget.record(false, &state);
        assert!(!budget.permits());
        let mut idle = RequestBudget::default();
        for _ in 0..6000 {
            idle.record(true, &Runtime::Pristine);
        }
        assert!(!idle.permits());
    }
    use serde_json::json;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn binding() -> Binding {
        Binding {
            session_id: "0123456789abcdef01234567".into(),
            nonce: "a".repeat(64),
        }
    }

    fn request(operation: &str) -> JobRequest {
        serde_json::from_value(json!({"protocol": PROTOCOL, "job_id": "123456789abcdef012345678", "operation": operation})).unwrap()
    }

    fn prepare() -> JobRequest {
        let mut r = request("prepare");
        r.prepare = Some(PrepareRequest {
            network: String::new(),
            binding: binding(),
            mode: "session".into(),
            ttl_ms: 10_000,
            input_files: vec![PrepareInput {
                path: "nested/prompt".into(),
                data: STANDARD.encode(b"\0hello\xff"),
                mode: 0o444,
            }],
        });
        r
    }

    fn roots() -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
        let id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("osv-pristine-{}-{id}", std::process::id()));
        let input = root.join("input");
        let workspace = root.join("workspace");
        fs::create_dir_all(&input).unwrap();
        fs::create_dir_all(&workspace).unwrap();
        (root, input, workspace)
    }

    fn remove(root: &Path) {
        fn writable(path: &Path) {
            for entry in fs::read_dir(path).unwrap() {
                let entry = entry.unwrap();
                if entry.file_type().unwrap().is_dir() {
                    writable(&entry.path());
                }
            }
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        writable(root);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn pristine_binding_and_input_permissions_commit_once() {
        let (root, input, workspace) = roots();
        let deadline = Instant::now() + SESSION_MAX_AGE;
        let mut state = Runtime::Pristine;
        let (ping, action) =
            state.dispatch(request("ping"), None, deadline, &input, &workspace, |_| {
                Ok(())
            });
        assert!(ping.ok);
        assert_eq!(ping.guest_state, Some("pristine"));
        assert_eq!(action, ConnectionAction::Continue);
        let (ready, action) =
            state.dispatch(prepare(), None, deadline, &input, &workspace, |_| Ok(()));
        assert!(ready.ok, "{:?}", ready.error);
        assert_eq!(action, ConnectionAction::Continue);
        assert_eq!(ready.binding, Some(binding()));
        assert_eq!(ready.guest_state, Some("prepared"));
        assert_eq!(
            fs::read(input.join("nested/prompt")).unwrap(),
            b"\0hello\xff"
        );
        assert_eq!(
            fs::metadata(input.join("nested/prompt")).unwrap().mode() & 0o777,
            0o444
        );
        assert_eq!(
            fs::metadata(input.join("nested")).unwrap().mode() & 0o777,
            0o555
        );
        let mut ping = request("ping");
        ping.binding = Some(binding());
        let (alive, _) = state.dispatch(ping, None, deadline, &input, &workspace, |_| Ok(()));
        assert!(alive.ok && alive.binding == Some(binding()));
        let (repeated, action) =
            state.dispatch(prepare(), None, deadline, &input, &workspace, |_| Ok(()));
        assert!(!repeated.ok);
        assert_eq!(action, ConnectionAction::Poweroff);
        assert!(matches!(state, Runtime::Poisoned));
        remove(&root);
    }

    #[test]
    fn pristine_rejects_execution_downgrade_and_wrong_nonce() {
        let deadline = Instant::now() + SESSION_MAX_AGE;
        for protocol in [super::super::PROTOCOL, SESSION_PROTOCOL, PROTOCOL] {
            let mut run = request("run");
            run.protocol = protocol.into();
            run.argv = vec![
                "/bin/sh".into(),
                "-c".into(),
                "printf should-not-execute".into(),
            ];
            run.timeout_ms = 1000;
            run.max_output_bytes = 4096;
            let mut state = Runtime::Pristine;
            let (result, action) = state.dispatch(
                run,
                None,
                deadline,
                Path::new("/missing"),
                Path::new("/missing"),
                |_| panic!("unexpected preparation"),
            );
            assert!(!result.ok && result.stdout.is_empty());
            assert_eq!(action, ConnectionAction::Poweroff);
        }
        let mut state = Runtime::Prepared {
            binding: binding(),
            deadline,
            one_shot: false,
        };
        let mut ping = request("ping");
        let mut wrong = binding();
        wrong.nonce = "b".repeat(64);
        ping.binding = Some(wrong);
        let (result, action) = state.dispatch(
            ping,
            None,
            deadline,
            Path::new("/missing"),
            Path::new("/missing"),
            |_| Ok(()),
        );
        assert!(!result.ok && result.binding.is_none());
        assert_eq!(action, ConnectionAction::Poweroff);
    }

    #[test]
    fn preparation_failure_is_terminal_and_rejects_dirty_roots() {
        let (root, input, workspace) = roots();
        let deadline = Instant::now() + SESSION_MAX_AGE;
        let mut state = Runtime::Pristine;
        let (result, action) =
            state.dispatch(prepare(), None, deadline, &input, &workspace, |_| {
                Err(io::Error::from_raw_os_error(libc::EROFS))
            });
        assert!(!result.ok);
        assert_eq!(action, ConnectionAction::Poweroff);
        let (retry, _) = state.dispatch(prepare(), None, deadline, &input, &workspace, |_| {
            panic!("poisoned VM reused")
        });
        assert!(!retry.ok);
        remove(&root);
        let (root, input, workspace) = roots();
        symlink("/etc/passwd", input.join("escape")).unwrap();
        assert!(stage_input(&input, &workspace, &[("safe".into(), b"x".to_vec())]).is_err());
        assert!(!input.join("safe").exists());
        remove(&root);
    }

    #[test]
    fn preparation_validates_all_inputs_before_writing() {
        let deadline = Instant::now() + SESSION_MAX_AGE;
        for bad in [
            "../escape",
            "/etc/passwd",
            "a//b",
            "a/./b",
            "a\\b",
            "bad\nname",
        ] {
            let mut r = prepare().prepare.unwrap();
            r.input_files[0].path = bad.into();
            assert!(validate_prepare(&r, deadline).is_err(), "accepted {bad}");
        }
        let mut r = prepare().prepare.unwrap();
        r.input_files = ["a", "a-", "a/b"]
            .map(|path| PrepareInput {
                path: path.into(),
                data: "eA==".into(),
                mode: 0,
            })
            .into();
        assert!(validate_prepare(&r, deadline).is_err());
        let mut r = prepare().prepare.unwrap();
        r.input_files[0].mode = 0o755;
        assert!(validate_prepare(&r, deadline).is_err());
        let mut r = prepare().prepare.unwrap();
        r.input_files[0].data = STANDARD.encode(vec![0u8; 512 * 1024 + 1]);
        assert!(validate_prepare(&r, deadline).is_err());
        let r = prepare().prepare.unwrap();
        assert!(validate_prepare(&r, Instant::now() + Duration::from_secs(5)).is_err());
    }

    #[test]
    #[ignore = "requires privileged QEMU validation guest"]
    fn pristine_real_readonly_mount() {
        assert_eq!(std::env::var("OSV_PRISTINE_MOUNT_TEST").as_deref(), Ok("1"));
        assert_eq!(unsafe { libc::geteuid() }, 0);
        let (root, input, workspace) = roots();
        let path = input.to_str().unwrap();
        mount_required(
            "tmpfs",
            path,
            "tmpfs",
            libc::MS_NODEV | libc::MS_NOSUID | libc::MS_NOEXEC,
            Some("size=4m,mode=0700"),
        )
        .unwrap();
        let mut state = Runtime::Pristine;
        let (result, _) = state.dispatch(
            prepare(),
            None,
            Instant::now() + SESSION_MAX_AGE,
            &input,
            &workspace,
            freeze_input,
        );
        assert!(result.ok, "{:?}", result.error);
        let error = fs::write(input.join("nested/prompt"), b"changed").unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EROFS));
        assert_eq!(
            fs::read(input.join("nested/prompt")).unwrap(),
            b"\0hello\xff"
        );
        let target = CString::new(input.to_str().unwrap()).unwrap();
        assert_eq!(unsafe { libc::umount2(target.as_ptr(), 0) }, 0);
        remove(&root);
    }
}
