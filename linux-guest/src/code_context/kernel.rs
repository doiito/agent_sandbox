use super::wire::{FRAME_LIMIT, Frame};
use super::*;
use crate::workload::{KernelIo, Process, Spec};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;

pub(super) struct Pump {
    pub frames: Vec<Frame>,
    pub output: Vec<(bool, Vec<u8>)>,
    pub ended: bool,
    pub control_closed: bool,
}
pub(super) struct Kernel {
    process: Process,
    io: KernelIo,
    pending: Vec<u8>,
    sent: usize,
    received: Vec<u8>,
    out_eof: bool,
    err_eof: bool,
    control_eof: bool,
}

fn error(_: impl fmt::Display) -> Error {
    Error::new("kernel_io", "interpreter IO failed")
}
fn nonblocking(fd: i32) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}
impl Kernel {
    pub fn spawn(context: &Context, options: &Options) -> Result<Self> {
        let python = context.language == Language::Python;
        let script = options
            .kernel_directory
            .join(if python { "python.py" } else { "node.cjs" });
        let argv = if python {
            vec![
                "/opt/python/bin/python3.12".into(),
                "-u".into(),
                "-B".into(),
                script.to_string_lossy().into_owned(),
            ]
        } else {
            vec![
                "/opt/node/bin/node".into(),
                script.to_string_lossy().into_owned(),
                context.language.name().into(),
            ]
        };
        let environment = BTreeMap::from([
            (
                "PATH".into(),
                "/opt/python/bin:/opt/node/bin:/usr/bin:/bin".into(),
            ),
            ("HOME".into(), "/workspace".into()),
            ("LANG".into(), "C.UTF-8".into()),
            ("PYTHONDONTWRITEBYTECODE".into(), "1".into()),
            ("OPENBLAS_NUM_THREADS".into(), "1".into()),
            ("OMP_NUM_THREADS".into(), "1".into()),
        ]);
        let (process, io) = Process::spawn_kernel(Spec {
            argv,
            environment,
            cwd: context.cwd.clone(),
        })
        .map_err(error)?;
        nonblocking(process.stdout.as_ref().unwrap().as_raw_fd()).map_err(error)?;
        nonblocking(process.stderr.as_ref().unwrap().as_raw_fd()).map_err(error)?;
        Ok(Self {
            process,
            io,
            pending: Vec::new(),
            sent: 0,
            received: Vec::new(),
            out_eof: false,
            err_eof: false,
            control_eof: false,
        })
    }
    pub fn pid(&self) -> Option<u32> {
        self.process.pid()
    }
    pub fn submit(&mut self, code: &str, env: &BTreeMap<String, String>) -> Result<()> {
        if !self.sent() {
            return Err(Error::new(
                "kernel_protocol",
                "interpreter request still pending",
            ));
        }
        let data =
            serde_json::to_vec(&serde_json::json!({"code":code,"env":env})).map_err(error)?;
        if data.len() > FRAME_LIMIT {
            return Err(Error::new(
                "invalid_request",
                "encoded code exceeds frame limit",
            ));
        }
        self.pending = (data.len() as u32).to_be_bytes().to_vec();
        self.pending.extend_from_slice(&data);
        self.sent = 0;
        Ok(())
    }
    pub fn sent(&self) -> bool {
        self.sent == self.pending.len()
    }
    pub fn interrupt(&mut self) -> Result<()> {
        self.process.interrupt().map_err(error)
    }
    pub fn interrupt_frame(&mut self, count: u64) -> Result<()> {
        if !self.sent() {
            return Err(error("request incomplete"));
        }
        let data = serde_json::to_vec(&serde_json::json!({"interrupt":count})).map_err(error)?;
        self.pending = (data.len() as u32).to_be_bytes().to_vec();
        self.pending.extend_from_slice(&data);
        self.sent = 0;
        Ok(())
    }
    pub fn stop(&mut self) {
        self.pending.clear();
        self.sent = 0;
        self.received.clear();
        self.process.stop();
    }
    pub fn clean(&self) -> bool {
        self.process.clean()
    }
    pub fn poll_fds(&self, output: &mut Vec<libc::pollfd>) {
        let mut add = |fd, events| {
            output.push(libc::pollfd {
                fd,
                events,
                revents: 0,
            })
        };
        add(
            self.process.control_fd(),
            libc::POLLIN
                | if self.process.wants_write() {
                    libc::POLLOUT
                } else {
                    0
                },
        );
        if !self.control_eof {
            add(self.io.output.as_raw_fd(), libc::POLLIN);
        }
        if !self.sent() {
            add(self.io.input.as_raw_fd(), libc::POLLOUT);
        }
        if !self.out_eof {
            add(
                self.process.stdout.as_ref().unwrap().as_raw_fd(),
                libc::POLLIN,
            );
        }
        if !self.err_eof {
            add(
                self.process.stderr.as_ref().unwrap().as_raw_fd(),
                libc::POLLIN,
            );
        }
    }

    fn drain_stdio(&mut self, stopping: bool, output: &mut Vec<(bool, Vec<u8>)>) -> Result<()> {
        for (reader, eof, stderr) in [
            (
                self.process.stdout.as_mut().unwrap() as &mut dyn Read,
                &mut self.out_eof,
                false,
            ),
            (
                self.process.stderr.as_mut().unwrap() as &mut dyn Read,
                &mut self.err_eof,
                true,
            ),
        ] {
            if *eof {
                continue;
            }
            for _ in 0..8 {
                let mut bytes = [0u8; 8192];
                match reader.read(&mut bytes) {
                    Ok(0) => {
                        *eof = true;
                        break;
                    }
                    Ok(n) => {
                        if !stopping {
                            output.push((stderr, bytes[..n].to_vec()));
                        }
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(error(e)),
                }
            }
        }
        Ok(())
    }

    pub fn pump(&mut self, stopping: bool) -> Result<Pump> {
        let ended = self
            .process
            .try_wait()
            .map_err(|_| Error::new("supervision", "workload supervision failed"))?
            .is_some();
        if !stopping && !ended {
            for _ in 0..8 {
                if self.sent() {
                    break;
                }
                match self.io.input.write(&self.pending[self.sent..]) {
                    Ok(0) => return Err(error("input closed")),
                    Ok(n) => {
                        self.sent += n;
                    }
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(error(e)),
                }
            }
        }
        let mut output = Vec::new();
        self.drain_stdio(stopping, &mut output)?;
        let mut frames = Vec::new();
        if !self.control_eof {
            for _ in 0..16 {
                let mut bytes = [0u8; 8192];
                match self.io.output.read(&mut bytes) {
                    Ok(0) => {
                        self.control_eof = true;
                        break;
                    }
                    Ok(n) if !stopping => self.received.extend_from_slice(&bytes[..n]),
                    Ok(_) => (),
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(error(e)),
                }
                while !stopping && self.received.len() >= 4 {
                    let size = u32::from_be_bytes(self.received[..4].try_into().unwrap()) as usize;
                    if size == 0 || size > FRAME_LIMIT {
                        return Err(Error::new(
                            "kernel_protocol",
                            "invalid language frame length",
                        ));
                    }
                    if self.received.len() < size + 4 {
                        break;
                    }
                    frames.push(Frame::parse(&self.received[4..size + 4])?);
                    self.received.drain(..size + 4);
                    if frames.len() > 32 {
                        return Err(Error::new(
                            "kernel_protocol",
                            "too many language frames per IO turn",
                        ));
                    }
                }
                if self.received.len() > FRAME_LIMIT + 4 {
                    return Err(Error::new(
                        "kernel_protocol",
                        "language frame buffer exceeded",
                    ));
                }
            }
        }
        if !stopping
            && frames
                .iter()
                .any(|frame| matches!(frame, Frame::Done { .. }))
        {
            self.drain_stdio(false, &mut output)?;
        }
        Ok(Pump {
            frames,
            output,
            ended,
            control_closed: self.control_eof,
        })
    }
}
