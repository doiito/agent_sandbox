use super::*;
use std::os::linux::net::SocketAddrExt;
use std::os::unix::net::{SocketAddr, UnixListener, UnixStream};
use std::sync::atomic::{AtomicU64, Ordering};

fn listener() -> (UnixListener, SocketAddr) {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let name = format!(
        "osv-accept-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    );
    let address = SocketAddr::from_abstract_name(name).unwrap();
    (UnixListener::bind_addr(&address).unwrap(), address)
}

#[test]
fn expired_deadline_does_not_access_listener() {
    let deadline = Instant::now() - Duration::from_millis(1);
    assert!(accept_host_vsock_until(-1, deadline).unwrap().is_none());
}

#[test]
fn empty_listener_waits_until_absolute_deadline_including_submillisecond() {
    let (listener, _) = listener();
    for wait in [Duration::from_micros(250), Duration::from_millis(25)] {
        let deadline = Instant::now() + wait;
        assert!(
            accept_host_vsock_until(listener.as_raw_fd(), deadline)
                .unwrap()
                .is_none()
        );
        assert!(Instant::now() >= deadline);
    }
}

#[test]
fn ready_non_socket_error_is_propagated() {
    let file = File::open("/dev/null").unwrap();
    let error = accept_host_vsock_until(file.as_raw_fd(), Instant::now() + Duration::from_secs(1))
        .unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::ENOTSOCK));
}

#[test]
fn non_vsock_peer_is_closed_and_does_not_extend_deadline() {
    let (listener, address) = listener();
    let mut client = UnixStream::connect_addr(&address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let deadline = Instant::now() + Duration::from_millis(10);
    assert!(
        accept_host_vsock_until(listener.as_raw_fd(), deadline)
            .unwrap()
            .is_none()
    );
    assert!(Instant::now() >= deadline);
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
}
