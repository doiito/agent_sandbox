/* SPDX-License-Identifier: BSD-3-Clause */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static unsigned checks, failures;

static void check(const char *name, int ok)
{
    ++checks;
    failures += !ok;
    printf("PIPE_STAT_CHECK name=%s passed=%d\n", name, !!ok);
}

static int snapshot(int fd, struct stat *value, const char *name)
{
    memset(value, 0xa5, sizeof(*value));
    errno = 0;
    int result = fstat(fd, value);
    int error = errno;
    int flags = fcntl(fd, F_GETFL);
    printf("PIPE_STAT_FD name=%s fd=%d result=%d errno=%d flags=%d\n",
           name, fd, result, error, flags);
    if (!result)
        printf("PIPE_STAT_META name=%s mode=%o dev=%llu inode=%llu uid=%u gid=%u\n",
               name, value->st_mode, (unsigned long long)value->st_dev,
               (unsigned long long)value->st_ino, value->st_uid, value->st_gid);
    return result == 0;
}

static int same_time(struct timespec a, struct timespec b)
{
    return a.tv_sec == b.tv_sec && a.tv_nsec == b.tv_nsec;
}

static void redirected_standard_stream(int stream)
{
    int pair[2], saved = dup(stream);
    int ok = saved >= 0 && pipe(pair) == 0;
    if (!ok) {
        if (saved >= 0) close(saved);
        check("standard-stream-setup", 0);
        return;
    }
    struct stat before, after;
    int original_stat = fstat(stream == STDIN_FILENO ? pair[0] : pair[1], &before);
    int replaced = dup2(stream == STDIN_FILENO ? pair[0] : pair[1], stream);
    int redirected_stat = replaced < 0 ? -1 : fstat(stream, &after);
    char value = 0;
    int io_ok;
    if (stream == STDIN_FILENO)
        io_ok = write(pair[1], "x", 1) == 1 && read(stream, &value, 1) == 1 && value == 'x';
    else
        io_ok = write(stream, "x", 1) == 1 && read(pair[0], &value, 1) == 1 && value == 'x';
    int restored = dup2(saved, stream);
    close(saved);
    close(pair[0]);
    close(pair[1]);
    check(stream == 0 ? "stdin-io" : stream == 1 ? "stdout-io" : "stderr-io", io_ok && restored >= 0);
    check(stream == 0 ? "stdin-stat" : stream == 1 ? "stdout-stat" : "stderr-stat",
          original_stat == 0 && redirected_stat == 0 && S_ISFIFO(after.st_mode) &&
          before.st_ino == after.st_ino && before.st_dev == after.st_dev);
}

struct concurrent_state {
    int reader;
    _Atomic unsigned errors;
    unsigned bytes;
};

static void *read_concurrently(void *opaque)
{
    struct concurrent_state *state = opaque;
    char buffer[31];
    ssize_t size;
    while ((size = read(state->reader, buffer, sizeof(buffer))) > 0) {
        state->bytes += (unsigned)size;
        for (ssize_t i = 0; i < size; ++i)
            if (buffer[i] != 'q') atomic_fetch_add(&state->errors, 1);
        struct stat info;
        if (fstat(state->reader, &info) || !S_ISFIFO(info.st_mode))
            atomic_fetch_add(&state->errors, 1);
    }
    if (size < 0) atomic_fetch_add(&state->errors, 1);
    return NULL;
}

static void concurrent_io(void)
{
    int pair[2];
    if (pipe(pair)) { check("concurrent-setup", 0); return; }
    struct concurrent_state state = {.reader = pair[0]};
    pthread_t reader;
    if (pthread_create(&reader, NULL, read_concurrently, &state)) {
        close(pair[0]); close(pair[1]); check("concurrent-thread", 0); return;
    }
    char payload[16];
    memset(payload, 'q', sizeof(payload));
    unsigned written = 0;
    for (unsigned i = 0; i < 4096; ++i) {
        if (write(pair[1], payload, sizeof(payload)) != sizeof(payload)) break;
        written += sizeof(payload);
        if ((i & 63) == 0) {
            struct stat info;
            if (fstat(pair[1], &info) || !S_ISFIFO(info.st_mode))
                atomic_fetch_add(&state.errors, 1);
        }
    }
    close(pair[1]);
    int joined = pthread_join(reader, NULL);
    close(pair[0]);
    check("concurrent-io", joined == 0 && written == 65536 && state.bytes == written);
    check("concurrent-stat", atomic_load(&state.errors) == 0);
}

static unsigned open_descriptors(void)
{
    unsigned count = 0;
    for (int fd = 0; fd < 1024; ++fd)
        if (fcntl(fd, F_GETFD) >= 0) ++count;
    return count;
}

static void nonblocking_and_lifetime(void)
{
    int pair[2];
    if (pipe2(pair, O_NONBLOCK)) { check("nonblocking-setup", 0); return; }
    char byte;
    errno = 0;
    check("nonblocking-empty", read(pair[0], &byte, 1) == -1 && errno == EAGAIN);
    check("zero-byte-io", read(pair[0], &byte, 0) == 0 && write(pair[1], "", 0) == 0);
    close(pair[0]);
    errno = 0;
    check("broken-pipe", write(pair[1], "x", 1) == -1 && errno == EPIPE);
    close(pair[1]);
    unsigned before = open_descriptors();
    unsigned successful = 0;
    ino_t previous = 0;
    for (unsigned i = 0; i < 128; ++i) {
        if (pipe(pair)) break;
        struct stat info;
        if (fstat(pair[0], &info) == 0 && info.st_ino > previous) {
            previous = info.st_ino;
            ++successful;
        }
        close(pair[0]); close(pair[1]);
    }
    check("repeated-distinct-pipes", successful == 128);
    check("no-fd-leak", before == open_descriptors());
    errno = 0;
    check("reject-invalid-flags", pipe2(pair, -1) == -1 && errno == EINVAL);
    check("invalid-flags-no-leak", before == open_descriptors());
}

int main(void)
{
    signal(SIGPIPE, SIG_IGN);
    int pair[2];
    if (pipe(pair)) { check("pipe", 0); return 1; }
    check("pipe", 1);
    struct stat a, b, copy, different, before_write, after_write, after_read;
    int a_ok = snapshot(pair[0], &a, "read-end");
    int b_ok = snapshot(pair[1], &b, "write-end");
    check("both-ends-fstat", a_ok && b_ok);
    check("fifo-metadata", a_ok && b_ok && S_ISFIFO(a.st_mode) && S_ISFIFO(b.st_mode) &&
          a.st_nlink == 1 && a.st_size == 0 && a.st_blksize > 0 &&
          a.st_uid == geteuid() && a.st_gid == getegid());
    check("shared-identity", a_ok && b_ok && a.st_ino && a.st_ino == b.st_ino && a.st_dev == b.st_dev);
    int duplicate = dup(pair[0]);
    check("dup-identity", duplicate >= 0 && fstat(duplicate, &copy) == 0 && a_ok &&
          copy.st_ino == a.st_ino && copy.st_dev == a.st_dev);
    if (duplicate >= 0) close(duplicate);
    char data[4] = {0};
    int io_ok = write(pair[1], "pipe", 4) == 4 && read(pair[0], data, 4) == 4 && !memcmp(data, "pipe", 4);
    check("pipe-roundtrip", io_ok);
    errno = 0;
    check("read-only-end", write(pair[0], "x", 1) == -1 && errno == EBADF);
    errno = 0;
    check("write-only-end", read(pair[1], data, 1) == -1 && errno == EBADF);
    errno = 0;
    check("nonseekable", lseek(pair[0], 0, SEEK_CUR) == -1 && errno == ESPIPE);
    errno = 0;
    check("nonterminal", isatty(pair[1]) == 0 && errno == ENOTTY);
    int other[2];
    int other_ok = pipe(other) == 0;
    check("distinct-identity", other_ok && a_ok && fstat(other[0], &different) == 0 &&
          (different.st_ino != a.st_ino || different.st_dev != a.st_dev));
    if (other_ok) { close(other[0]); close(other[1]); }
    int before_ok = fstat(pair[0], &before_write) == 0;
    struct timespec delay = {.tv_nsec = 2000000};
    nanosleep(&delay, NULL);
    int wrote = write(pair[1], "t", 1) == 1;
    int wrote_stat = fstat(pair[1], &after_write) == 0;
    nanosleep(&delay, NULL);
    int read_ok = read(pair[0], data, 1) == 1;
    int read_stat = fstat(pair[0], &after_read) == 0;
    check("creation-time-write", before_ok && wrote && wrote_stat &&
          same_time(before_write.st_mtim, after_write.st_mtim) &&
          after_write.st_mtim.tv_sec >= 0 && after_write.st_mtim.tv_nsec >= 0 && after_write.st_mtim.tv_nsec < 1000000000);
    check("creation-time-read", wrote_stat && read_ok && read_stat &&
          same_time(after_write.st_atim, after_read.st_atim) &&
          after_read.st_atim.tv_sec >= 0 && after_read.st_atim.tv_nsec >= 0 && after_read.st_atim.tv_nsec < 1000000000);
    close(pair[1]);
    check("eof", read(pair[0], data, 1) == 0);
    int closed = pair[0]; close(pair[0]);
    errno = 0;
    check("closed-fd", fstat(closed, &a) == -1 && errno == EBADF);
    errno = 0;
    check("invalid-fd", fstat(-1, &a) == -1 && errno == EBADF);
    errno = 0;
    check("invalid-isatty", isatty(-1) == 0 && errno == EBADF);
    for (int stream = 0; stream < 3; ++stream) redirected_standard_stream(stream);
    concurrent_io();
    nonblocking_and_lifetime();
    printf("PIPE_STAT_PROBE_END checks=%u failed=%u\n", checks, failures);
    fflush(NULL);
    return failures ? 1 : 0;
}
