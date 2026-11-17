/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef OSV_SANDBOX_RUN_H
#define OSV_SANDBOX_RUN_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Loads one module already present in the signed guest image. Returns zero
 * and writes the module's exit code on success; otherwise returns -errno.
 * This API does not make the module an isolated process or security principal.
 * argc includes argv[0]: at most 65 entries and 32768 string bytes in total.
 */
int osv_sandbox_run_module(const char *path, const char *const *argv,
                           size_t argc, int *exit_code);

#define OSV_SANDBOX_EXIT_ABI 1u
typedef void (*osv_sandbox_exit_callback)(void *context, int status);

/* One registration for this single-use VM. No reset/unregister: context must
 * live until VM shutdown. The callback completes the original task response
 * and returns before the existing VM shutdown. All errors are negative errno.
 */
int osv_sandbox_register_exit_callback(uint32_t version,
                                      osv_sandbox_exit_callback callback,
                                      void *context);

#ifdef __cplusplus
}
#endif
#endif
