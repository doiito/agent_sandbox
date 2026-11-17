//! Trusted, bounded command output and cancellation on the execution connection.
use super::pristine::Binding;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Serialize;
use std::fs::File;
use std::io::{self, Write};
use std::os::fd::AsRawFd;

pub(super) const EVENT_PREFIX: &str = "FC_AGENT_EVENT ";
pub(super) const MAX_EVENTS: u64 = 256;

pub(super) struct StreamWriter {
    file: File,
    protocol: &'static str,
    job_id: String,
    binding: Option<Binding>,
    sequence: u64,
    control: Vec<u8>,
    pub(super) cancelled: bool,
    stdin: crate::command_stdin::StdinState,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{JobRequest, JobResult, KillScope, SESSION_PROTOCOL, supervise_child_stream};
    use std::io::{BufRead, BufReader};
    use std::os::fd::{FromRawFd, IntoRawFd};
    use std::os::unix::{net::UnixStream, process::CommandExt};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    fn launch(
        script: &str,
        limit: usize,
        buffered: Vec<u8>,
    ) -> (UnixStream, mpsc::Receiver<JobResult>) {
        launch_with_input(script, limit, buffered, false)
    }

    fn launch_with_input(
        script: &str,
        limit: usize,
        buffered: Vec<u8>,
        interactive: bool,
    ) -> (UnixStream, mpsc::Receiver<JobResult>) {
        let (client, server) = UnixStream::pair().unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (send, receive) = mpsc::channel();
        let script = script.to_owned();
        std::thread::spawn(move || {
            let request = JobRequest {
                protocol: SESSION_PROTOCOL.into(),
                job_id: "0123456789abcdef01234567".into(),
                operation: Some("run_stream".into()),
                argv: vec!["/bin/sh".into()],
                timeout_ms: 5000,
                max_output_bytes: limit,
                file: None,
                binding: None,
                prepare: None,
                environment: Default::default(),
                cwd: None,
                interactive_stdin: interactive,
                stdin: None,
            };
            let mut command = Command::new("/bin/sh");
            command
                .args(["-c", &script])
                .stdin(if interactive {
                    Stdio::piped()
                } else {
                    Stdio::null()
                })
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
            let file = unsafe { File::from_raw_fd(server.into_raw_fd()) };
            let writer = StreamWriter::new(file, &request, buffered).unwrap();
            let child = command.spawn().unwrap();
            if let Some(pipe) = child.stdin.as_ref() {
                assert_eq!(
                    unsafe { libc::fcntl(pipe.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) },
                    4096
                );
            }
            let result = supervise_child_stream(
                child,
                &request,
                Instant::now(),
                KillScope::ProcessGroup,
                Some(writer),
            );
            send.send(result).unwrap();
        });
        (client, receive)
    }

    #[test]
    fn output_is_live_binary_and_ordered_before_exit() {
        let gate = std::env::temp_dir().join(format!("osv-stream-gate-{}", std::process::id()));
        let _ = std::fs::remove_file(&gate);
        let script = format!(
            "printf '\\000\\377first'; while ! test -f '{}'; do sleep 0.01; done; printf error >&2; printf last",
            gate.display()
        );
        let (client, done) = launch(&script, 4096, vec![]);
        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let started: serde_json::Value =
            serde_json::from_str(line.strip_prefix("FC_AGENT_STARTED ").unwrap()).unwrap();
        assert!(started["pid"].as_u64().unwrap() > 1);
        line.clear();
        reader.read_line(&mut line).unwrap();
        let event: serde_json::Value =
            serde_json::from_str(line.strip_prefix(EVENT_PREFIX).unwrap()).unwrap();
        assert_eq!(event["sequence"], 1);
        assert_eq!(
            STANDARD
                .decode(event["data_base64"].as_str().unwrap())
                .unwrap(),
            b"\x00\xfffirst"
        );
        assert!(done.try_recv().is_err());
        std::fs::write(&gate, b"release").unwrap();
        let mut sequence = 1;
        loop {
            line.clear();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }
            let event: serde_json::Value =
                serde_json::from_str(line.strip_prefix(EVENT_PREFIX).unwrap()).unwrap();
            sequence += 1;
            assert_eq!(event["sequence"], sequence);
        }
        let result = done.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(result.ok);
        assert_eq!(result.stderr, "error");
        assert!(result.stdout.ends_with("firstlast"));
        std::fs::remove_file(gate).unwrap();
    }

    #[test]
    fn cancellation_acknowledges_process_cleanup() {
        let (mut client, done) = launch("printf ready; sleep 30", 4096, vec![]);
        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        client.write_all(b"can").unwrap();
        client.write_all(b"cel\n").unwrap();
        let result = done.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(!result.ok && !result.timed_out);
        assert_eq!(result.error.as_deref(), Some("command cancelled"));
        assert_eq!(result.exit_code, 137);
    }

    #[test]
    fn prefetched_cancel_and_silent_transport_loss_do_not_wait_for_command_timeout() {
        let (_client, done) = launch("sleep 30", 4096, b"cancel\n".to_vec());
        let result = done.recv_timeout(Duration::from_secs(5)).unwrap();
        assert_eq!(result.error.as_deref(), Some("command cancelled"));
        let (client, done) = launch("sleep 30", 4096, vec![]);
        drop(client);
        let result = done.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(!result.ok && !result.timed_out);
    }

    #[test]
    fn output_flood_is_drained_and_explicitly_truncated() {
        let (mut client, done) = launch("yes stream | head -c 200000", 1024, vec![]);
        let mut bytes = Vec::new();
        std::io::Read::read_to_end(&mut client, &mut bytes).unwrap();
        let result = done.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(result.ok && result.output_truncated);
        assert_eq!(result.stdout.len() + result.stderr.len(), 1024);
        assert!(bytes.len() < 4096);
    }
    fn input(sequence: u32, data: &[u8], close: bool) -> Vec<u8> {
        let value = serde_json::json!({"protocol":SESSION_PROTOCOL,"job_id":"0123456789abcdef01234567","sequence":sequence,"data_base64":STANDARD.encode(data),"close":close});
        let mut frame = serde_json::to_vec(&value).unwrap();
        frame.push(b'\n');
        frame
    }
    fn next_frame(reader: &mut BufReader<UnixStream>) -> (String, serde_json::Value) {
        let mut line = String::new();
        assert!(reader.read_line(&mut line).unwrap() > 0);
        let (kind, data) = line.split_once(' ').unwrap();
        (kind.into(), serde_json::from_str(data).unwrap())
    }
    #[test]
    fn stdin_binary_fragments_and_eof_reach_the_actual_process() {
        let (mut client, done) = launch_with_input("cat; printf eof >&2", 4096, vec![], true);
        let mut reader = BufReader::new(client.try_clone().unwrap());
        assert_eq!(next_frame(&mut reader).0, "FC_AGENT_STARTED");
        let bytes: Vec<u8> = (0..=255).cycle().take(1024).collect();
        for part in input(1, &bytes, false).chunks(3) {
            client.write_all(part).unwrap();
        }
        let mut output = Vec::new();
        loop {
            let (kind, value) = next_frame(&mut reader);
            if kind == "FC_AGENT_STDIN" {
                assert_eq!(value["sequence"], 1);
                assert_eq!(value["written_bytes"], 1024);
                assert!(value["error_code"].is_null());
                break;
            }
            if kind == "FC_AGENT_EVENT" && value["stream"] == "stdout" {
                output.extend(
                    STANDARD
                        .decode(value["data_base64"].as_str().unwrap())
                        .unwrap(),
                );
            }
        }
        client.write_all(&input(2, b"", true)).unwrap();
        let mut closed = false;
        loop {
            let mut line = String::new();
            if reader.read_line(&mut line).unwrap() == 0 {
                break;
            }
            let (kind, data) = line.split_once(' ').unwrap();
            let value: serde_json::Value = serde_json::from_str(data).unwrap();
            if kind == "FC_AGENT_STDIN" {
                assert_eq!(value["sequence"], 2);
                assert_eq!(value["closed"], true);
                closed = true;
            }
            if kind == "FC_AGENT_EVENT" && value["stream"] == "stdout" {
                output.extend(
                    STANDARD
                        .decode(value["data_base64"].as_str().unwrap())
                        .unwrap(),
                );
            }
        }
        let result = done.recv_timeout(Duration::from_secs(5)).unwrap();
        assert!(closed && result.ok);
        assert_eq!(output, bytes);
        assert_eq!(result.stderr, "eof");
    }
    #[test]
    fn backpressured_stdin_keeps_output_and_cancellation_live() {
        let (mut client, done) = launch_with_input("printf ready; sleep 30", 4096, vec![], true);
        let mut reader = BufReader::new(client.try_clone().unwrap());
        assert_eq!(next_frame(&mut reader).0, "FC_AGENT_STARTED");
        client
            .write_all(&input(1, &vec![b'x'; 16384], false))
            .unwrap();
        let (kind, value) = next_frame(&mut reader);
        assert_eq!(kind, "FC_AGENT_EVENT");
        assert_eq!(value["data_base64"], STANDARD.encode(b"ready"));
        std::thread::sleep(Duration::from_millis(40));
        assert!(done.try_recv().is_err());
        let started = Instant::now();
        client.write_all(b"cancel\n").unwrap();
        let (kind, ack) = next_frame(&mut reader);
        assert_eq!(kind, "FC_AGENT_STDIN");
        assert_eq!(ack["error_code"], "command_exited");
        assert_eq!(ack["written_bytes"], 4096);
        let result = done.recv_timeout(Duration::from_secs(2)).unwrap();
        assert_eq!(result.exit_code, 137);
        assert!(started.elapsed() < Duration::from_secs(1));
    }
    #[test]
    fn invalid_stdin_control_does_not_reach_the_process() {
        for bad in ["job", "sequence", "oversize", "disabled"] {
            let (mut client, done) =
                launch_with_input("cat; sleep 30", 4096, vec![], bad != "disabled");
            let mut reader = BufReader::new(client.try_clone().unwrap());
            assert_eq!(next_frame(&mut reader).0, "FC_AGENT_STARTED");
            let mut frame: serde_json::Value =
                serde_json::from_slice(&input(1, b"forbidden", false)).unwrap();
            match bad {
                "job" => frame["job_id"] = "ffffffffffffffffffffffff".into(),
                "sequence" => frame["sequence"] = 2.into(),
                "oversize" => frame["data_base64"] = STANDARD.encode(vec![0; 16385]).into(),
                _ => {}
            }
            writeln!(client, "{frame}").unwrap();
            let result = done.recv_timeout(Duration::from_secs(2)).unwrap();
            assert!(!result.ok);
            assert!(result.stdout.is_empty());
        }
    }
}

#[derive(Serialize)]
struct Event<'a> {
    protocol: &'static str,
    job_id: &'a str,
    sequence: u64,
    stream: &'static str,
    data_base64: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    binding: &'a Option<Binding>,
}

impl StreamWriter {
    pub(super) fn new(
        file: File,
        request: &super::JobRequest,
        buffered_control: Vec<u8>,
    ) -> io::Result<Self> {
        let timeout = libc::timeval {
            tv_sec: 1,
            tv_usec: 0,
        };
        if unsafe {
            libc::setsockopt(
                file.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_SNDTIMEO,
                &timeout as *const _ as *const libc::c_void,
                std::mem::size_of_val(&timeout) as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            file,
            protocol: super::result_protocol(&request.protocol),
            job_id: request.job_id.clone(),
            binding: request.binding.clone(),
            sequence: 0,
            control: buffered_control,
            cancelled: false,
            stdin: crate::command_stdin::StdinState::new(request.interactive_stdin),
        })
    }

    pub(super) fn started(&mut self, pid: u32) -> io::Result<()> {
        let frame = serde_json::json!({"protocol":self.protocol,"job_id":self.job_id,"pid":pid,"binding":self.binding});
        writeln!(self.file, "FC_AGENT_STARTED {frame}")?;
        self.file.flush()
    }

    pub(super) fn has_capacity(&self) -> bool {
        self.sequence < MAX_EVENTS
    }

    pub(super) fn emit(&mut self, stdout: bool, bytes: &[u8]) -> io::Result<()> {
        if bytes.is_empty() {
            return Ok(());
        }
        self.sequence += 1;
        let event = Event {
            protocol: self.protocol,
            job_id: &self.job_id,
            sequence: self.sequence,
            stream: if stdout { "stdout" } else { "stderr" },
            data_base64: STANDARD.encode(bytes),
            binding: &self.binding,
        };
        let encoded = serde_json::to_string(&event)?;
        writeln!(self.file, "{EVENT_PREFIX}{encoded}")?;
        self.file.flush()
    }

    pub(super) fn attach_stdin(
        &mut self,
        pipe: Option<std::process::ChildStdin>,
    ) -> io::Result<()> {
        self.stdin.attach(pipe)
    }
    fn input_ack(&mut self, ack: crate::command_stdin::InputAck) -> io::Result<()> {
        let frame = serde_json::json!({"protocol":self.protocol,"job_id":self.job_id,"binding":self.binding,
            "sequence":ack.sequence,"written_bytes":ack.written_bytes,"closed":ack.closed,"error_code":ack.error_code});
        writeln!(self.file, "FC_AGENT_STDIN {frame}")?;
        self.file.flush()
    }
    pub(super) fn finish_stdin(&mut self) -> io::Result<()> {
        if let Some(ack) = self.stdin.finish() {
            self.input_ack(ack)?;
        }
        Ok(())
    }
    pub(super) fn check_control(&mut self) -> io::Result<()> {
        // One bounded read per tick leaves time for stdout/stderr and child reaping.
        let mut bytes = [0_u8; 4096];
        let count = unsafe {
            libc::recv(
                self.file.as_raw_fd(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
                libc::MSG_DONTWAIT,
            )
        };
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "command control transport disconnected",
            ));
        }
        if count < 0 {
            let error = io::Error::last_os_error();
            if !matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
            ) {
                return Err(error);
            }
        } else {
            self.control.extend_from_slice(&bytes[..count as usize]);
        }
        if self.control.len() > 32768 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "command control exceeds limit",
            ));
        }
        while let Some(end) = self.control.iter().position(|b| *b == b'\n') {
            let frame: Vec<u8> = self.control.drain(..=end).collect();
            if frame == b"cancel\n" {
                self.cancelled = true;
                return Err(io::Error::new(
                    io::ErrorKind::Interrupted,
                    "command cancelled",
                ));
            }
            self.stdin
                .accept(&frame, self.protocol, &self.job_id, &self.binding)?;
            if let Some(ack) = self.stdin.progress() {
                self.input_ack(ack)?;
            }
        }
        if let Some(ack) = self.stdin.progress() {
            self.input_ack(ack)?;
        }
        Ok(())
    }
}
