/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef OSV_SANDBOX_VSOCK_API_H
#define OSV_SANDBOX_VSOCK_API_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__)
#define OSV_VSOCK_EXPORT __attribute__((visibility("default")))
#else
#define OSV_VSOCK_EXPORT
#endif

/* Handles are private to this single-address-space VM, not security tokens.
 * All errors are negative errno. timeout_ms=0 never blocks; max is 300000.
 * Initial transport supports modern MMIO and peer CID 2 (Firecracker host).
 */
OSV_VSOCK_EXPORT int osv_vsock_listen(uint32_t port, unsigned backlog);
OSV_VSOCK_EXPORT int osv_vsock_accept(int listener, uint32_t timeout_ms);
OSV_VSOCK_EXPORT int osv_vsock_connect(uint64_t cid, uint32_t port, uint32_t timeout_ms);
OSV_VSOCK_EXPORT int64_t osv_vsock_recv(int connection, void* data, size_t size, uint32_t timeout_ms);
OSV_VSOCK_EXPORT int64_t osv_vsock_send(int connection, const void* data, size_t size, uint32_t timeout_ms);
OSV_VSOCK_EXPORT int osv_vsock_shutdown(int connection, uint32_t flags);
OSV_VSOCK_EXPORT int osv_vsock_close(int handle);
OSV_VSOCK_EXPORT uint64_t osv_vsock_cid(void);

#undef OSV_VSOCK_EXPORT

#ifdef __cplusplus
}
#endif
#endif
