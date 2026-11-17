/* SPDX-License-Identifier: BSD-3-Clause */
/* Real-kernel mount probe. Kept in a diagnostic image, outside release guests. */
#include <osv/sandbox-input.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

static unsigned checks, failed;
static void check(const char *name, int passed)
{
    ++checks;
    if (!passed) ++failed;
    printf("INPUT_MOUNT_CHECK name=%s passed=%d errno=%d\n", name, !!passed, errno);
}

static int denied(int result)
{
    return result == -1 && (errno == EROFS || errno == EACCES || errno == EPERM || errno == EXDEV);
}

int main(int argc, char **argv)
{
    const int empty = argc >= 2 && !strcmp(argv[1], "empty");
    struct osv_input_view bad = {(const uint8_t *)"../escape", 9, NULL, 0};
    check("reject-traversal-before-mount", osv_sandbox_mount_inputs_v1(&bad, 1) == EINVAL);
    bad.path = (const uint8_t *)"file"; bad.path_length = 4;
    struct osv_input_view duplicate[] = {bad, bad};
    check("reject-duplicate-before-mount", osv_sandbox_mount_inputs_v1(duplicate, 2) == EINVAL);
    check("reject-count-before-mount", osv_sandbox_mount_inputs_v1(&bad, 65) == EINVAL);
    check("reject-null-before-mount", osv_sandbox_mount_inputs_v1(NULL, 1) == EINVAL);

    if (empty) {
        check("mount-empty", osv_sandbox_mount_inputs_v1(NULL, 0) == 0);
    } else {
        uint8_t *bytes = malloc(OSV_INPUT_MAX_DATA_BYTES);
        char (*paths)[1025] = calloc(OSV_INPUT_MAX_FILES, 1025);
        struct osv_input_view files[OSV_INPUT_MAX_FILES];
        if (!bytes || !paths) return 90;
        for (size_t i = 0; i < OSV_INPUT_MAX_DATA_BYTES; ++i) bytes[i] = (uint8_t)(i % 251);
        size_t cursor = 0;
        for (unsigned i = 0; i < OSV_INPUT_MAX_FILES; ++i) {
            snprintf(paths[i], 1025, "nested/file-%02u", i);
            if (!i) strcpy(paths[i], "nested/\xe4\xb8\xad\xe6\x96\x87/binary");
            if (i == OSV_INPUT_MAX_FILES-1) {
                size_t position = 0;
                const unsigned lengths[] = {255,255,255,254,1};
                for (unsigned n = 0; n < 5; ++n) {
                    if (n) paths[i][position++] = '/';
                    memset(paths[i]+position, 'a'+n, lengths[n]);
                    position += lengths[n];
                }
                paths[i][position] = 0;
            }
            unsigned size = i == 0 ? 16384 : i == 1 ? 0 : 8192;
            files[i] = (struct osv_input_view){(const uint8_t *)paths[i], (uint16_t)strlen(paths[i]), bytes+cursor, size};
            cursor += size;
        }
        check("exact-data-budget", cursor == OSV_INPUT_MAX_DATA_BYTES);
        check("mount-max-files-and-bytes", osv_sandbox_mount_inputs_v1(files, OSV_INPUT_MAX_FILES) == 0);
        memset(bytes, 255, OSV_INPUT_MAX_DATA_BYTES);
        free(bytes);
        unsigned valid = 0;
        cursor = 0;
        for (unsigned i = 0; i < OSV_INPUT_MAX_FILES; ++i) {
            char path[1032];
            snprintf(path, sizeof(path), "/input/%s", paths[i]);
            struct stat info;
            int fd = open(path, O_RDONLY);
            int ok = fd >= 0 && !fstat(fd, &info) && info.st_size == files[i].data_length && (info.st_mode & 0777) == 0444;
            size_t offset = 0;
            uint8_t buffer[1024];
            if (fd >= 0) {
                ssize_t size;
                while ((size = read(fd, buffer, sizeof(buffer))) > 0) {
                    for (ssize_t j = 0; j < size; ++j) if (buffer[j] != (cursor+offset+(size_t)j)%251) ok = 0;
                    offset += size;
                }
                ok = ok && size == 0 && offset == files[i].data_length;
                close(fd);
            }
            if (ok) ++valid;
            cursor += files[i].data_length;
        }
        check("all-files-own-data-after-source-free", valid == OSV_INPUT_MAX_FILES);
        free(paths);
        const char *file = "/input/nested/\xe4\xb8\xad\xe6\x96\x87/binary";
        int fd = open(file, O_WRONLY); check("deny-write-open", denied(fd)); if (fd >= 0) close(fd);
        fd = open(file, O_RDWR); check("deny-readwrite-open", denied(fd)); if (fd >= 0) close(fd);
        fd = open(file, O_WRONLY|O_TRUNC); check("deny-truncate-open", denied(fd)); if (fd >= 0) close(fd);
        check("deny-truncate", denied(truncate(file, 0)));
        check("deny-unlink", denied(unlink(file)));
        check("deny-rename", denied(rename(file, "/input/moved")));
        check("deny-cross-mount-rename", denied(rename(file, "/tmp/moved")));
        check("deny-chmod", denied(chmod(file, 0666)));
        check("deny-chown", denied(chown(file, 1, 1)));
        check("deny-lchown", denied(lchown(file, 1, 1)));
        fd = open(file, O_RDONLY);
        check("readonly-descriptor-open", fd >= 0);
        check("deny-fchown", denied(fchown(fd, 1, 1)));
        check("deny-ftruncate", denied(ftruncate(fd, 0)));
        if (fd >= 0) close(fd);
        check("deny-utimes", denied(utimes(file, NULL)));
        check("deny-link", denied(link(file, "/input/linked")));
        check("deny-cross-mount-link", denied(link(file, "/tmp/linked")));
        struct stat info;
        check("existing-file-still-intact", !stat(file, &info) && info.st_size == 16384 && (info.st_mode & 0777) == 0444);
    }
    int fd = open("/input/created", O_WRONLY|O_CREAT, 0666);
    check("deny-create", denied(fd)); if (fd >= 0) close(fd);
    check("deny-mkdir", denied(mkdir("/input/new-directory", 0777)));
    check("deny-symlink", denied(symlink("/tmp", "/input/new-link")));
    check("deny-root-chmod", denied(chmod("/input", 0777)));
    struct stat info;
    check("root-mode", !stat("/input", &info) && S_ISDIR(info.st_mode) && (info.st_mode & 0777) == 0555);
    check("no-created-file", stat("/input/created", &info) == -1 && errno == ENOENT);
    check("deny-replacement-mount", osv_sandbox_mount_inputs_v1(NULL, 0) == EBUSY);
    printf("INPUT_MOUNT_END mode=%s checks=%u failed=%u\n", empty ? "empty" : "maximum", checks, failed);
    fflush(stdout);
    return failed ? 1 : 0;
}
