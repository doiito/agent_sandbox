/* SPDX-License-Identifier: BSD-3-Clause */
/* Fixed, in-image module for verifying OSv application loading over vsock. */
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdatomic.h>
#include <string.h>
#include <unistd.h>
#include <osv/sandbox-run.h>
#include <errno.h>

static atomic_int background_ready;

static void rejected_exit_replacement(void *opaque, int status)
{
    (void)opaque;
    (void)status;
}

static void *explicit_exit_worker(void *unused)
{
    (void)unused;
    static const char marker[] = "OSV_NATIVE_THREAD_EXIT\n";
    if (write(STDOUT_FILENO, marker, sizeof(marker) - 1) != sizeof(marker) - 1) _Exit(98);
    _Exit(19);
}

static void *hold_output_fd(void *unused)
{
    (void)unused;
    int held = dup(STDOUT_FILENO);
    atomic_store(&background_ready, held >= 0 ? 1 : -1);
    sleep(10);
    if (held >= 0) close(held);
    return NULL;
}

int main(int argc, char **argv)
{
    if (argc == 65 && strcmp(argv[1], "native-many-args") == 0) {
        for (int index = 2; index < argc; ++index) {
            char expected[16];
            snprintf(expected, sizeof(expected), "arg-%02d", index - 1);
            if (strcmp(argv[index], expected)) return 65;
        }
        puts("OSV_NATIVE_64_ARGS_OK");
        fflush(stdout);
        return 0;
    }
    if (argc != 2) return 64;
    if (strcmp(argv[1], "native-explicit-exit") == 0) {
        static const char marker[] = "OSV_NATIVE_EXPLICIT_EXIT\n";
        if (write(STDOUT_FILENO, marker, sizeof(marker) - 1) != sizeof(marker) - 1) return 98;
        exit(23);
    }
    if (strcmp(argv[1], "native-immediate-exit") == 0) {
        int duplicate = dup(STDOUT_FILENO);
        if (duplicate < 0) return 98;
        FILE *buffered = fdopen(duplicate, "w");
        if (!buffered || setvbuf(buffered, NULL, _IOFBF, 4096)) return 98;
        fputs("OSV_MUST_NOT_FLUSH", buffered);
        static const char marker[] = "OSV_NATIVE_IMMEDIATE_EXIT\n";
        if (write(STDERR_FILENO, marker, sizeof(marker) - 1) != sizeof(marker) - 1) return 98;
        _Exit(29);
    }
    if (strcmp(argv[1], "native-thread-exit") == 0 || strcmp(argv[1], "native-exit-race") == 0) {
        pthread_t worker;
        if (pthread_create(&worker, NULL, explicit_exit_worker, NULL)) return 70;
        if (strcmp(argv[1], "native-exit-race") == 0) return 0;
        sleep(10);
        return 71;
    }
    if (strcmp(argv[1], "native-exit-binding-locked") == 0) {
        /* Correct registration cannot be replaced by a task. */
        static int cookie;
        if (osv_sandbox_register_exit_callback(OSV_SANDBOX_EXIT_ABI, rejected_exit_replacement, &cookie) != -EALREADY)
            return 80;
        puts("OSV_NATIVE_EXIT_BINDING_LOCKED");
        fflush(stdout);
        return 0;
    }
    if (strcmp(argv[1], "native-task") == 0) {
        puts("OSV_NATIVE_MODULE_RAN");
        fflush(stdout);
        return 7;
    }
    if (strcmp(argv[1], "native-success") == 0) {
        puts("OSV_NATIVE_MODULE_OK");
        fflush(stdout);
        return 0;
    }
    if (strcmp(argv[1], "native-env") == 0) {
        const char *marker = getenv("SANDBOX_TEST_MARKER");
        const char *empty = getenv("SANDBOX_EMPTY");
        if (!marker || strcmp(marker, "native-env-ok") || !empty || *empty)
            return 72;
        puts("OSV_NATIVE_ENV_OK");
        fflush(stdout);
        return 0;
    }
    if (strcmp(argv[1], "native-env-absent") == 0) {
        if (getenv("SANDBOX_TEST_MARKER") || getenv("SANDBOX_EMPTY"))
            return 73;
        puts("OSV_NATIVE_ENV_ABSENT");
        fflush(stdout);
        return 0;
    }
    if (strcmp(argv[1], "native-stdin-empty") == 0) {
        if (getchar() != EOF) return 74;
        puts("OSV_NATIVE_STDIN_EMPTY_OK");
        return 0;
    }
    if (strcmp(argv[1], "native-stdin-binary") == 0 ||
        strcmp(argv[1], "native-env-stdin") == 0) {
        const unsigned char expected[] = {'A', 0, 'B', 0xff, '\n'};
        for (unsigned index = 0; index < sizeof(expected); ++index) {
            if (getchar() != expected[index]) return 75;
        }
        if (getchar() != EOF) return 76;
        if (strcmp(argv[1], "native-env-stdin") == 0) {
            const char *marker = getenv("SANDBOX_TEST_MARKER");
            if (!marker || strcmp(marker, "native-env-ok")) return 77;
        }
        puts("OSV_NATIVE_STDIN_BINARY_OK");
        return 0;
    }
    if (strcmp(argv[1], "native-stdin-max") == 0) {
        for (unsigned index = 0; index < 16384; ++index) {
            if (getchar() != (int)(index % 251)) return 78;
        }
        if (getchar() != EOF) return 79;
        puts("OSV_NATIVE_STDIN_MAX_OK");
        return 0;
    }
    if (strcmp(argv[1], "native-stdin-ignore") == 0) {
        puts("OSV_NATIVE_STDIN_IGNORE_OK");
        return 0;
    }
    if (strcmp(argv[1], "native-stderr") == 0) {
        fputs("OSV_NATIVE_STDERR\n", stderr);
        fflush(stderr);
        return 0;
    }
    if (strcmp(argv[1], "native-flood") == 0) {
        char chunk[4096];
        memset(chunk, 'F', sizeof(chunk));
        for (unsigned i = 0; i < 32; ++i) fwrite(chunk, 1, sizeof(chunk), stdout);
        fflush(stdout);
        return 0;
    }
    if (strcmp(argv[1], "native-sleep") == 0) {
        sleep(10);
        return 0;
    }
    if (strcmp(argv[1], "native-background-fd") == 0) {
        pthread_t worker;
        if (pthread_create(&worker, NULL, hold_output_fd, NULL)) return 70;
        pthread_detach(worker);
        for (unsigned attempt = 0; attempt < 1000 && !atomic_load(&background_ready); ++attempt)
            usleep(1000);
        if (atomic_load(&background_ready) != 1) return 71;
        puts("OSV_NATIVE_BACKGROUND_MAIN_DONE");
        fflush(stdout);
        return 0;
    }
    if (strcmp(argv[1], "native-crash") == 0) abort();
    return 64;
}
