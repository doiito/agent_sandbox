/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef OSV_RAMFS_READONLY_INPUTS_HH
#define OSV_RAMFS_READONLY_INPUTS_HH

#include <osv/sandbox-input.h>
#include <cstring>

#define OSV_INPUT_RAMFS_DEVICE "osv-sandbox-input-v1"

struct vnode;
struct ramfs_input_mount_data {
    const osv_input_view *files;
    size_t count;
};

int ramfs_import_readonly_inputs(vnode *root, const ramfs_input_mount_data *data);

#endif
