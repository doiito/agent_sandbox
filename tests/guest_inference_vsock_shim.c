/* Test-only ABI shim: real ctypes signatures and partial TCP I/O, not OSv. */
#define _POSIX_C_SOURCE 200809L
#include "../osv-native/include/osv/vsock.h"
#include <arpa/inet.h>
#include <errno.h>
#include <stdatomic.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

static _Atomic int connects, sends, recvs, interruptions, shutdowns;
static _Thread_local int send_interrupted, recv_interrupted;
static int timeout(int fd, uint32_t milliseconds) {
    if (!milliseconds || milliseconds > 300000) return -EINVAL;
    struct timeval value = {.tv_sec = milliseconds / 1000, .tv_usec = (milliseconds % 1000) * 1000};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &value, sizeof value) ||
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &value, sizeof value)) return -errno;
    return 0;
}
int osv_vsock_connect(uint64_t cid, uint32_t port, uint32_t milliseconds) {
    if (cid != 2 || port != 5001) return -EINVAL;
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return -errno;
    int error = timeout(fd, milliseconds);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(3128), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (!error && connect(fd, (struct sockaddr *)&address, sizeof address)) error = -errno;
    if (error) { close(fd); return error; }
    atomic_fetch_add(&connects, 1);
    return fd;
}
int64_t osv_vsock_send(int fd, const void *data, size_t size, uint32_t milliseconds) {
    if (!send_interrupted++) { atomic_fetch_add(&interruptions, 1); return -EINTR; }
    int error = timeout(fd, milliseconds);
    if (error) return error;
    ssize_t count = send(fd, data, size < 7 ? size : 7, MSG_NOSIGNAL);
    atomic_fetch_add(&sends, 1);
    return count < 0 ? -errno : count;
}
int64_t osv_vsock_recv(int fd, void *data, size_t size, uint32_t milliseconds) {
    if (!recv_interrupted++) { atomic_fetch_add(&interruptions, 1); return -EINTR; }
    int error = timeout(fd, milliseconds);
    if (error) return error;
    ssize_t count = recv(fd, data, size < 2047 ? size : 2047, 0);
    atomic_fetch_add(&recvs, 1);
    return count < 0 ? -errno : count;
}
int osv_vsock_shutdown(int fd, uint32_t flags) {
    (void)fd; (void)flags; atomic_fetch_add(&shutdowns, 1); return -ENOTSUP;
}
int osv_vsock_close(int fd) { return close(fd) ? -errno : 0; }
int osv_test_connects(void) { return atomic_load(&connects); }
int osv_test_sends(void) { return atomic_load(&sends); }
int osv_test_recvs(void) { return atomic_load(&recvs); }
int osv_test_interruptions(void) { return atomic_load(&interruptions); }
int osv_test_shutdowns(void) { return atomic_load(&shutdowns); }
