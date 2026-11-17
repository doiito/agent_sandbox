/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef OSV_SANDBOX_INPUT_MOUNT_V1_H
#define OSV_SANDBOX_INPUT_MOUNT_V1_H

#include <osv/input-files.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Agent/kernel ABI, never a wire structure. Returns an error number (0 on
 * success). The kernel copies every file before returning to the agent.
 */
int osv_sandbox_mount_inputs_v1(const struct osv_input_view *files, size_t count);

#ifdef __cplusplus
}
#endif
#endif
