/* SPDX-License-Identifier: BSD-3-Clause
 * Included after ramfs_add_node: reuse its node/inode accounting, while the
 * private tree is not yet published by sys_mount().
 */
#include "readonly-inputs.hh"
#include <osv/export.h>
#include <memory>
#include <new>

/* Keep the RAMFS debug macro namespace; vfs/vfs.h declares this mount entry
 * alongside a different DPRINTF macro and is not safe to include mid-TU.
 */
extern "C" int sys_mount(const char *dev, const char *dir, const char *fsname, int flags, const void *data);

namespace {
bool input_views_valid(const osv_input_view *files, size_t count)
{
    if (count > OSV_INPUT_MAX_FILES || (count && !files)) return false;
    size_t paths = 0, bytes = 0;
    for (size_t i = 0; i < count; ++i) {
        const auto& item = files[i];
        if (!item.path || (item.data_length && !item.data) ||
            item.path_length > OSV_INPUT_MAX_PATH_BYTES - paths ||
            item.data_length > OSV_INPUT_MAX_DATA_BYTES - bytes ||
            osv_input_path(item.path, item.path_length)) return false;
        for (size_t j = 0; j < i; ++j) {
            size_t a = item.path_length, b = files[j].path_length;
            size_t shorter = a < b ? a : b;
            if (!memcmp(item.path, files[j].path, shorter) &&
                (a == b || (a < b && files[j].path[a] == '/') ||
                 (b < a && item.path[b] == '/'))) return false;
        }
        paths += item.path_length;
        bytes += item.data_length;
    }
    return true;
}

void input_destroy_tree(ramfs_node *node)
{
    if (!node) return;
    for (auto child = node->rn_child; child;) {
        auto next = child->rn_next;
        input_destroy_tree(child);
        child = next;
    }
    node->rn_removed = true;
    ramfs_free_node(node);
}

struct input_free_buffer {
    void operator()(char *value) const { free(value); }
};

int input_populate(ramfs_node *root, const osv_input_view *files, size_t count)
{
    root->rn_mode = S_IFDIR | 0555;
    for (size_t i = 0; i < count; ++i) {
        const auto& item = files[i];
        auto directory = root;
        size_t start = 0;
        for (size_t end = 0; end <= item.path_length; ++end) {
            if (end < item.path_length && item.path[end] != '/') continue;
            const bool last = end == item.path_length;
            const size_t length = end - start;
            char component[256];
            memcpy(component, item.path + start, length);
            component[length] = '\0';
            auto node = directory->rn_child;
            for (; node && strcmp(node->rn_name, component); node = node->rn_next) {}
            if (node && (last || node->rn_type != VDIR)) return EEXIST;
            if (!node) {
                node = ramfs_add_node(directory, component, last ? VREG : VDIR);
                if (!node) return ENOMEM;
                node->rn_mode = last ? (S_IFREG | 0444) : (S_IFDIR | 0555);
            }
            if (last) {
                if (item.data_length) {
                    std::unique_ptr<char, input_free_buffer> bytes(static_cast<char *>(malloc(item.data_length)));
                    if (!bytes) return ENOMEM;
                    memcpy(bytes.get(), item.data, item.data_length);
                    node->rn_file_segments_by_offset->emplace(0, ramfs_file_segment{item.data_length, bytes.get()});
                    bytes.release();
                }
                node->rn_size = item.data_length;
                node->rn_total_segments_size = item.data_length;
            } else {
                directory = node;
            }
            start = end + 1;
        }
    }
    return 0;
}
}

int ramfs_import_readonly_inputs(vnode *root, const ramfs_input_mount_data *data)
{
    int error = EINVAL;
    try {
        if (data && input_views_valid(data->files, data->count))
            error = input_populate(static_cast<ramfs_node *>(root->v_data), data->files, data->count);
    } catch (const std::bad_alloc&) {
        error = ENOMEM;
    } catch (...) {
        error = EIO;
    }
    if (error) {
        input_destroy_tree(static_cast<ramfs_node *>(root->v_data));
        root->v_data = nullptr;
    } else {
        root->v_mode = S_IFDIR | 0555;
    }
    return error;
}

extern "C" OSV_MODULE_API
int osv_sandbox_mount_inputs_v1(const osv_input_view *files, size_t count)
{
    if (!input_views_valid(files, count)) return EINVAL;
    const ramfs_input_mount_data data{files, count};
    return sys_mount(OSV_INPUT_RAMFS_DEVICE, "/input", "ramfs", MNT_RDONLY, &data);
}
