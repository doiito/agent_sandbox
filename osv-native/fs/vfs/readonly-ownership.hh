/* SPDX-License-Identifier: BSD-3-Clause
 * OSv has no per-file uid/gid ownership. Preserve its writable-filesystem
 * no-op, but reject metadata changes on readonly mounts and invalid handles.
 * Included in main.cc after task_conv(), alongside the ownership wrappers.
 */
static int readonly_ownership_path(const char *pathname, bool nofollow)
{
    if (!pathname) return ENOENT;
    char path[PATH_MAX];
    int error = task_conv(main_task, pathname, VWRITE, path);
    if (error) return error;
    struct dentry *entry = nullptr;
    if (nofollow) {
        struct dentry *parent = nullptr;
        error = lookup(path, &parent, nullptr);
        if (error) return error;
        error = namei_last_nofollow(path, parent, &entry);
        drele(parent);
    } else {
        error = namei(path, &entry);
    }
    if (error) return error;
    error = (entry->d_mount->m_flags & MNT_RDONLY) ? EROFS : 0;
    drele(entry);
    return error;
}

static int readonly_ownership_fd(int fd)
{
    fileref file(fileref_from_fd(fd));
    if (!file) return EBADF;
    return file->f_dentry && (file->f_dentry->d_mount->m_flags & MNT_RDONLY) ? EROFS : 0;
}
