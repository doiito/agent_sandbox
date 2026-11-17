use super::*;
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

pub(crate) const VSOCK_PROXY_PORT: u32 = 5001;
const LOCAL_PROXY: &str = "http://127.0.0.1:3128";
const CONNECTIONS: usize = 8;
const TIMEOUT: Duration = Duration::from_secs(35);
static ENABLED: AtomicBool = AtomicBool::new(false);

pub(crate) fn configure_command(command: &mut Command) {
    if ENABLED.load(Ordering::Acquire) {
        apply_proxy_environment(command);
    }
}

fn apply_proxy_environment(command: &mut Command) {
    for name in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        command.env(name, LOCAL_PROXY);
    }
    command.env("NO_PROXY", "").env("no_proxy", "");
}

pub(crate) fn enable() -> io::Result<()> {
    if unsafe { libc::getpid() } != 1 || ENABLED.load(Ordering::Acquire) {
        return Err(io::Error::other("guest proxy can be bound once by PID 1"));
    }
    enable_loopback()?;
    let listener = TcpListener::bind("127.0.0.1:3128")?;
    thread::Builder::new()
        .name("egress-listener".into())
        .spawn(move || {
            let active = Arc::new(AtomicUsize::new(0));
            for accepted in listener.incoming() {
                let Ok(mut client) = accepted else { break };
                if active.fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| (n < CONNECTIONS).then_some(n + 1)).is_err() {
                    let _ = client.set_write_timeout(Some(Duration::from_millis(100)));
                    let _ = client.write_all(b"HTTP/1.1 503 Busy\r\nConnection: close\r\nContent-Length: 0\r\n\r\n");
                    continue;
                }
                let owned = active.clone();
                if thread::Builder::new().name("egress-relay".into()).spawn(move || {
                    struct Release(Arc<AtomicUsize>);
                    impl Drop for Release {
                        fn drop(&mut self) { self.0.fetch_sub(1, Ordering::AcqRel); }
                    }
                    let _release = Release(owned);
                    let _ = client.set_read_timeout(Some(TIMEOUT));
                    let _ = client.set_write_timeout(Some(TIMEOUT));
                    match connect_host() {
                        Ok(host) => { let _ = relay(client, host); }
                        Err(_) => { let _ = client.write_all(b"HTTP/1.1 503 Egress unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"); }
                    }
                }).is_err() {
                    active.fetch_sub(1, Ordering::AcqRel);
                }
            }
        })?;
    ENABLED.store(true, Ordering::Release);
    Ok(())
}

pub(crate) fn enable_loopback() -> io::Result<()> {
    let fd = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let _socket = unsafe { File::from_raw_fd(fd) };
    let mut interface: libc::ifreq = unsafe { std::mem::zeroed() };
    interface.ifr_name[0] = b'l' as libc::c_char;
    interface.ifr_name[1] = b'o' as libc::c_char;
    if unsafe { libc::ioctl(fd, libc::SIOCGIFFLAGS as _, &mut interface) } < 0 {
        return Err(io::Error::last_os_error());
    }
    unsafe {
        interface.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
    }
    if unsafe { libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &interface) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

fn connect_host() -> io::Result<File> {
    let fd = unsafe { libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let socket = unsafe { File::from_raw_fd(fd) };
    let connect_timeout = libc::timeval {
        tv_sec: 1,
        tv_usec: 0,
    };
    if unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDTIMEO,
            &connect_timeout as *const _ as *const libc::c_void,
            std::mem::size_of_val(&connect_timeout) as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let mut address: libc::sockaddr_vm = unsafe { std::mem::zeroed() };
    address.svm_family = libc::AF_VSOCK as libc::sa_family_t;
    address.svm_cid = libc::VMADDR_CID_HOST;
    address.svm_port = VSOCK_PROXY_PORT;
    if unsafe {
        libc::connect(
            fd,
            &address as *const _ as *const libc::sockaddr,
            std::mem::size_of_val(&address) as libc::socklen_t,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    let timeout = libc::timeval {
        tv_sec: TIMEOUT
            .as_secs()
            .try_into()
            .expect("fixed timeout fits timeval"),
        tv_usec: 0,
    };
    for option in [libc::SO_RCVTIMEO, libc::SO_SNDTIMEO] {
        if unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                option,
                &timeout as *const _ as *const libc::c_void,
                std::mem::size_of_val(&timeout) as libc::socklen_t,
            )
        } < 0
        {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(socket)
}

fn relay(mut client: TcpStream, mut host: File) -> io::Result<()> {
    let mut client_read = client.try_clone()?;
    let mut host_write = host.try_clone()?;
    let client_fd = client.as_raw_fd();
    let host_fd = host.as_raw_fd();
    thread::scope(|scope| {
        let outgoing = scope.spawn(move || {
            let result = io::copy(&mut client_read, &mut host_write);
            let _ = client_read.shutdown(Shutdown::Both);
            unsafe {
                libc::shutdown(host_fd, libc::SHUT_RDWR);
            }
            result
        });
        let result = io::copy(&mut host, &mut client);
        unsafe {
            libc::shutdown(client_fd, libc::SHUT_RDWR);
            libc::shutdown(host_fd, libc::SHUT_RDWR);
        }
        let outgoing_result = outgoing
            .join()
            .map_err(|_| io::Error::other("proxy relay thread failed"))?;
        result.and(outgoing_result).map(|_| ())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::IntoRawFd;
    use std::os::unix::net::UnixStream;

    #[test]
    #[ignore = "requires the explicitly selected privileged ARM64 QEMU fixture"]
    fn qemu_loopback_ioctl_and_vsock_failure_are_bounded() {
        assert_eq!(
            std::env::var("OSV_GUEST_PROXY_IOCTL_TEST").as_deref(),
            Ok("1")
        );
        assert!(std::env::consts::ARCH == "aarch64");
        enable_loopback().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        assert_ne!(listener.local_addr().unwrap().port(), 0);
        let started = Instant::now();
        // This no-NIC fixture has no host vsock endpoint. The real ARM64
        // syscall must fail promptly and release any socket it created.
        assert!(connect_host().is_err());
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn proxy_environment_is_explicit_and_caller_can_override() {
        let mut command = Command::new("/bin/true");
        apply_proxy_environment(&mut command);
        command.env("HTTPS_PROXY", "http://127.0.0.1:9000");
        let values: BTreeMap<_, _> = command.get_envs().collect();
        assert_eq!(values.len(), 6);
        assert_eq!(
            values[std::ffi::OsStr::new("http_proxy")],
            Some(std::ffi::OsStr::new(LOCAL_PROXY))
        );
        assert_eq!(
            values[std::ffi::OsStr::new("HTTPS_PROXY")],
            Some(std::ffi::OsStr::new("http://127.0.0.1:9000"))
        );
        assert_eq!(
            values[std::ffi::OsStr::new("NO_PROXY")],
            Some(std::ffi::OsStr::new(""))
        );
    }

    #[test]
    fn loopback_to_host_relay_preserves_binary_and_closes_both_sides() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let mut client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let (accepted, _) = listener.accept().unwrap();
        let (host, mut upstream) = UnixStream::pair().unwrap();
        upstream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let worker = thread::spawn(move || {
            relay(accepted, unsafe { File::from_raw_fd(host.into_raw_fd()) })
        });
        let request = b"POST http://allowed/ HTTP/1.1\r\nContent-Length: 3\r\n\r\n\x00\xffA";
        client.write_all(request).unwrap();
        let mut received = vec![0; request.len()];
        upstream.read_exact(&mut received).unwrap();
        assert_eq!(received, request);
        upstream.write_all(b"\x00\xffreply").unwrap();
        let mut response = [0; 7];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"\x00\xffreply");
        client.shutdown(Shutdown::Both).unwrap();
        let mut byte = [0];
        assert_eq!(upstream.read(&mut byte).unwrap(), 0);
        let _ = worker.join().unwrap();
    }
}
