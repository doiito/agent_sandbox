/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef OSV_AGENT_PRISTINE_INPUTS_H
#define OSV_AGENT_PRISTINE_INPUTS_H

#include "pristine.h"

typedef int (*osp_input_mount_fn)(const struct osv_input_view *, size_t, void *);
typedef uint64_t (*osp_input_clock_fn)(void *);

/* Commit the binding only after the complete input tree has been copied and
 * mounted readonly. A failure is terminal for the VM, never a retry point.
 */
static inline int osp_control_transaction(struct osp_state *state,
    const uint8_t *body, size_t length, uint64_t now, uint8_t response[OSP_RESPONSE_SIZE],
    osp_input_mount_fn mount_inputs, osp_input_clock_fn clock_now, void *opaque)
{
    struct osp_state candidate = *state;
    if (!clock_now || osp_control(&candidate, body, length, now, response)) return -1;
    if (candidate.revision == 2 && candidate.prepared) {
        struct osv_input_view files[OSV_INPUT_MAX_FILES];
        size_t count;
        if (!mount_inputs || osv_input_decode(body + OSP_REQUEST_SIZE,
            length - OSP_REQUEST_SIZE, files, &count) || mount_inputs(files, count, opaque)) return -1;
    }
    uint32_t remaining = osp_remaining(&candidate, clock_now(opaque));
    if (!remaining) return -1;
    osp_store32(response + 56, remaining);
    *state = candidate;
    return 0;
}

#endif
