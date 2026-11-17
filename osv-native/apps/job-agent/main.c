/* SPDX-License-Identifier: BSD-3-Clause */
/* One request per VM. The host remains authoritative for timeout and cleanup. */
#include <osv/sandbox-run.h>
#include <osv/sandbox-input.h>
#include <osv/vsock.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/reboot.h>
#include <time.h>
#include <unistd.h>
#include "pristine.h"
#include "pristine-inputs.h"
#include "completion.h"

#define REQUEST_MAX 65536u
#define CAPTURE_MAX (1024u * 1024u)
#define ARG_MAX_COUNT 64u
#define ENV_MAX_COUNT 32u
#define ENV_MAX_BYTES 8192u
#define STDIN_MAX_BYTES 16384u
#define REQUEST_FIXED 60u
#define RESULT_FIXED 64u

static atomic_uint_fast64_t pristine_deadline;
static atomic_uint_fast64_t task_transfer_deadline;
static uint64_t monotonic_ms(void);

static uint64_t input_clock(void *unused)
{
    (void)unused;
    return monotonic_ms();
}

static int mount_inputs(const struct osv_input_view *files, size_t count, void *unused)
{
    (void)unused;
    return osv_sandbox_mount_inputs_v1(files, count);
}

static uint32_t transfer_timeout_ms(void)
{
    uint64_t deadline = atomic_load_explicit(&pristine_deadline, memory_order_relaxed);
    uint64_t task_limit = atomic_load_explicit(&task_transfer_deadline, memory_order_relaxed);
    if (task_limit && (!deadline || task_limit < deadline)) deadline = task_limit;
    if (!deadline) return 30000;
    uint64_t now = monotonic_ms();
    if (!now || now >= deadline) return 0;
    uint64_t remaining = deadline - now;
    return (uint32_t)(remaining > 30000 ? 30000 : remaining);
}

struct job_request {
    char id[25];
    uint8_t nonce[16];
    uint32_t timeout_ms;
    uint32_t max_capture;
    char path[256];
    char *argv[ARG_MAX_COUNT + 1];
    unsigned argc;
    char *env_names[ENV_MAX_COUNT];
    char *env_values[ENV_MAX_COUNT];
    unsigned env_count;
    uint8_t *stdin_data;
    unsigned stdin_length;
    int stdin_present;
};

struct stdin_state {
    int writer;
    const uint8_t *data;
    size_t length;
    atomic_int stop;
};

struct capture_state {
    int read_fd[2];
    uint8_t *data[2];
    size_t used[2];
    size_t total;
    size_t max;
    int truncated[2];
    atomic_int stop;
};

struct job_result {
    int32_t status;
    int32_t exit_code;
    struct capture_state capture;
};

struct capture_scope {
    int pipes[2][2];
    int saved[2];
    int stdin_pair[2];
    int saved_stdin;
    int stdin_started;
    int reader_started;
    int redirected;
    struct stdin_state input;
    pthread_t feeder;
    pthread_t reader;
};

struct task_context {
    const struct job_request *request;
    struct job_result *result;
    int peer;
    int listener;
    uint64_t completion_deadline;
    struct osc_completion completion;
    struct capture_scope scope;
};

static void task_exit_callback(void *opaque, int status);

static _Noreturn void shutdown_guest(void)
{
    reboot(RB_POWER_OFF);
    // Do not return while the exit callback still refers to main's context.
    for (;;) {
        const struct timespec delay = {.tv_nsec = 100000000};
        nanosleep(&delay, NULL);
    }
}

static void wait_task_completion(struct task_context *task)
{
    while (!osc_completion_done(&task->completion)) {
        uint64_t now = monotonic_ms();
        if (!now || now >= task->completion_deadline) shutdown_guest();
        const struct timespec delay = {.tv_nsec = 1000000};
        nanosleep(&delay, NULL);
    }
}

static uint16_t load16(const uint8_t *p)
{
    return (uint16_t)p[0] | (uint16_t)p[1] << 8;
}

static uint32_t load32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
        (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void store32(uint8_t *p, uint32_t value)
{
    for (unsigned index = 0; index < 4; ++index) p[index] = (uint8_t)(value >> (8 * index));
}

static int receive_all(int peer, void *buffer, size_t size)
{
    uint8_t *next = buffer;
    while (size) {
        uint32_t timeout = transfer_timeout_ms();
        if (!timeout) return -1;
        int64_t count = osv_vsock_recv(peer, next, size, timeout);
        if (count <= 0) return -1;
        next += count;
        size -= (size_t)count;
    }
    return 0;
}

static int send_all(int peer, const void *buffer, size_t size)
{
    const uint8_t *next = buffer;
    while (size) {
        uint32_t timeout = transfer_timeout_ms();
        if (!timeout) return -1;
        int64_t count = osv_vsock_send(peer, next, size, timeout);
        if (count <= 0) return -1;
        next += count;
        size -= (size_t)count;
    }
    return 0;
}

static void free_request(struct job_request *request)
{
    for (unsigned index = 1; index < request->argc; ++index) free(request->argv[index]);
    for (unsigned index = 0; index < request->env_count; ++index) {
        free(request->env_names[index]);
        free(request->env_values[index]);
    }
    free(request->stdin_data);
}

static int valid_env_name(const char *name, size_t length)
{
    if (!length || length > 64 ||
        (length >= 3 && !memcmp(name, "LD_", 3)) ||
        (length >= 4 && !memcmp(name, "OSV_", 4))) return 0;
    for (size_t index = 0; index < length; ++index) {
        char ch = name[index];
        int letter = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z');
        if (!letter && !(ch == '_' || (index && ch >= '0' && ch <= '9'))) return 0;
    }
    return 1;
}

static int parse_request(const uint8_t *body, size_t length, struct job_request *request)
{
    if (length < REQUEST_FIXED || memcmp(body, "OSJ1", 4) || body[4] != 1 ||
        (body[5] & ~3u) || body[6] || body[7]) return -1;
    memcpy(request->id, body + 8, 24);
    request->id[24] = '\0';
    for (unsigned index = 0; index < 24; ++index) {
        char ch = request->id[index];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return -1;
    }
    memcpy(request->nonce, body + 32, 16);
    request->timeout_ms = load32(body + 48);
    request->max_capture = load32(body + 52);
    unsigned path_length = load16(body + 56);
    unsigned argument_count = load16(body + 58);
    if (!request->timeout_ms || request->timeout_ms > 300000 ||
        !request->max_capture || request->max_capture > CAPTURE_MAX ||
        path_length < 5 || path_length >= sizeof(request->path) ||
        argument_count > ARG_MAX_COUNT || REQUEST_FIXED + path_length > length)
        return -1;
    memcpy(request->path, body + REQUEST_FIXED, path_length);
    if (memchr(request->path, '\0', path_length)) return -1;
    request->path[path_length] = '\0';
    request->argv[0] = request->path;
    request->argc = 1;
    size_t offset = REQUEST_FIXED + path_length;
    /* The module path is argv[0] and shares the 32 KiB ABI budget. */
    size_t argument_bytes = path_length;
    for (unsigned index = 0; index < argument_count; ++index) {
        if (offset + 2 > length) return -1;
        unsigned size = load16(body + offset);
        offset += 2;
        if (size > 4096 || offset + size > length || argument_bytes + size > 32768 ||
            memchr(body + offset, '\0', size)) return -1;
        char *argument = malloc(size + 1);
        if (!argument) return -1;
        memcpy(argument, body + offset, size);
        argument[size] = '\0';
        request->argv[request->argc++] = argument;
        argument_bytes += size;
        offset += size;
    }
    if (body[5] & 1u) {
        if (offset + 2 > length) return -1;
        unsigned count = load16(body + offset);
        offset += 2;
        if (!count || count > ENV_MAX_COUNT) return -1;
        size_t total = 0;
        for (unsigned index = 0; index < count; ++index) {
            if (offset + 4 > length) return -1;
            unsigned name_length = load16(body + offset);
            unsigned value_length = load16(body + offset + 2);
            offset += 4;
            if (!name_length || name_length > 64 || value_length > 1024 ||
                name_length + value_length > length - offset ||
                total + name_length + value_length > ENV_MAX_BYTES ||
                memchr(body + offset, '\0', name_length + value_length) ||
                !valid_env_name((const char *)(body + offset), name_length)) return -1;
            char *name = malloc(name_length + 1);
            char *value = malloc(value_length + 1);
            if (!name || !value) {
                free(name);
                free(value);
                return -1;
            }
            memcpy(name, body + offset, name_length);
            name[name_length] = '\0';
            memcpy(value, body + offset + name_length, value_length);
            value[value_length] = '\0';
            if (index && strcmp(request->env_names[index - 1], name) >= 0) {
                free(name);
                free(value);
                return -1;
            }
            request->env_names[request->env_count] = name;
            request->env_values[request->env_count++] = value;
            offset += name_length + value_length;
            total += name_length + value_length;
        }
    }
    if (body[5] & 2u) {
        if (offset + 2 > length) return -1;
        unsigned size = load16(body + offset);
        offset += 2;
        if (size > STDIN_MAX_BYTES || size > length - offset) return -1;
        request->stdin_data = malloc(size ? size : 1);
        if (!request->stdin_data) return -1;
        if (size) memcpy(request->stdin_data, body + offset, size);
        request->stdin_length = size;
        request->stdin_present = 1;
        offset += size;
    }
    return offset == length ? 0 : -1;
}

static int read_request(int peer, struct job_request *request)
{
    uint8_t prefix[4];
    if (receive_all(peer, prefix, sizeof(prefix))) return -1;
    uint32_t length = load32(prefix);
    if (length < REQUEST_FIXED || length > REQUEST_MAX) return -1;
    uint8_t *body = malloc(length);
    if (!body) return -1;
    int result = receive_all(peer, body, length);
    if (!result) result = parse_request(body, length, request);
    free(body);
    return result;
}

static uint64_t monotonic_ms(void)
{
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}

static void *pristine_watchdog(void *unused)
{
    (void)unused;
    for (;;) {
        uint64_t deadline = atomic_load_explicit(&pristine_deadline, memory_order_relaxed);
        uint64_t now = monotonic_ms();
        if (!now || !deadline || now >= deadline) {
            reboot(RB_POWER_OFF);
            _exit(124);
        }
        uint64_t delay = deadline - now;
        if (delay > 100) delay = 100;
        struct timespec pause = {0, (long)delay * 1000000};
        nanosleep(&pause, NULL);
    }
    return NULL;
}

static int wait_pristine_job(int listener, struct osp_state *state,
                             struct job_request *request)
{
    for (;;) {
        uint32_t remaining = osp_remaining(state, monotonic_ms());
        if (!remaining) return -1;
        int peer = osv_vsock_accept(listener, remaining > 300000 ? 300000 : remaining);
        /* A 300-second accept timeout must not shorten the 600-second boot lease. */
        if (peer == -ETIMEDOUT && osp_remaining(state, monotonic_ms())) continue;
        if (peer < 0) return -1;
        uint8_t prefix[4];
        uint8_t *body = NULL;
        int result = receive_all(peer, prefix, sizeof(prefix));
        uint32_t length = result ? 0 : load32(prefix);
        uint32_t maximum = !state->prepared && state->revision == 2 ? OSP_INPUT_REQUEST_MAX : REQUEST_MAX;
        if (!result && (length < 48 || length > maximum)) result = -1;
        if (!result) {
            body = malloc(length);
            if (!body) result = -1;
        }
        if (!result) result = receive_all(peer, body, length);
        if (!result && state->prepared) {
            result = osp_consume_job(state, body, length, monotonic_ms());
            if (!result) result = parse_request(body, length, request);
            free(body);
            if (!result) return peer;
        } else if (!result) {
            uint8_t response[OSP_RESPONSE_SIZE];
            result = osp_control_transaction(state, body, length, monotonic_ms(), response,
                mount_inputs, input_clock, NULL);
            free(body);
            if (!result && state->prepared)
                atomic_store_explicit(&pristine_deadline, state->lease_deadline, memory_order_relaxed);
            if (!result) {
                uint8_t frame[4 + OSP_RESPONSE_SIZE];
                store32(frame, OSP_RESPONSE_SIZE);
                memcpy(frame + 4, response, sizeof(response));
                result = send_all(peer, frame, sizeof(frame));
            }
            uint8_t ack;
            if (!result) result = receive_all(peer, &ack, 1) || ack != 0xa5;
            if (!result) result = osv_vsock_shutdown(peer, 2);
            osv_vsock_close(peer);
            if (!result) continue;
            return -1;
        } else {
            free(body);
        }
        osv_vsock_close(peer);
        return -1;
    }
}

static void *capture_reader(void *opaque)
{
    struct capture_state *capture = opaque;
    uint64_t stopping_at = 0;
    for (;;) {
        struct pollfd fds[2] = {
            {capture->read_fd[0], POLLIN | POLLHUP, 0},
            {capture->read_fd[1], POLLIN | POLLHUP, 0},
        };
        int ready = poll(fds, 2, 20);
        if (ready < 0 && errno != EINTR) break;
        int received = 0;
        for (unsigned stream = 0; stream < 2; ++stream) {
            if (capture->read_fd[stream] < 0 || !fds[stream].revents) continue;
            uint8_t chunk[4096];
            ssize_t count = read(capture->read_fd[stream], chunk, sizeof(chunk));
            if (count == 0) {
                capture->read_fd[stream] = -1;
                continue;
            }
            if (count < 0) {
                if (errno != EAGAIN && errno != EINTR) capture->read_fd[stream] = -1;
                continue;
            }
            received = 1;
            size_t room = capture->max - capture->total;
            size_t kept = (size_t)count < room ? (size_t)count : room;
            if (kept) {
                memcpy(capture->data[stream] + capture->used[stream], chunk, kept);
                capture->used[stream] += kept;
                capture->total += kept;
            }
            if (kept < (size_t)count) capture->truncated[stream] = 1;
        }
        if (capture->read_fd[0] < 0 && capture->read_fd[1] < 0) break;
        if (atomic_load(&capture->stop)) {
            if (!stopping_at) stopping_at = monotonic_ms();
            if (!received || monotonic_ms() - stopping_at >= 50) break;
        }
    }
    return NULL;
}

static void *feed_stdin(void *opaque)
{
    struct stdin_state *input = opaque;
    sigset_t blocked;
    sigemptyset(&blocked);
    sigaddset(&blocked, SIGPIPE);
    if (pthread_sigmask(SIG_BLOCK, &blocked, NULL)) {
        close(input->writer);
        return NULL;
    }
    size_t offset = 0;
    while (offset < input->length && !atomic_load(&input->stop)) {
        ssize_t sent = write(input->writer, input->data + offset,
                             input->length - offset);
        if (sent > 0) {
            offset += (size_t)sent;
            continue;
        }
        if (sent < 0 && errno == EINTR) continue;
        if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd ready = {input->writer, POLLOUT, 0};
            poll(&ready, 1, 20);
            continue;
        }
        break;
    }
    close(input->writer);
    return NULL;
}

static void close_capture(struct task_context *task, int flush_stdio)
{
    struct capture_scope *scope = &task->scope;
    struct capture_state *capture = &task->result->capture;
    if (flush_stdio) fflush(NULL);
    if (scope->saved_stdin >= 0) dup2(scope->saved_stdin, STDIN_FILENO);
    if (scope->stdin_pair[0] >= 0) {
        close(scope->stdin_pair[0]);
        scope->stdin_pair[0] = -1;
    }
    if (scope->stdin_started) {
        atomic_store(&scope->input.stop, 1);
        pthread_join(scope->feeder, NULL);
    }
    if (scope->saved_stdin >= 0) close(scope->saved_stdin);
    if (!scope->stdin_started && scope->stdin_pair[1] >= 0) close(scope->stdin_pair[1]);
    for (int stream = 0; stream < scope->redirected; ++stream) {
        if (scope->saved[stream] >= 0) dup2(scope->saved[stream], stream + 1);
    }
    for (unsigned stream = 0; stream < 2; ++stream) {
        if (scope->saved[stream] >= 0) close(scope->saved[stream]);
        if (scope->pipes[stream][1] >= 0) close(scope->pipes[stream][1]);
    }
    if (scope->reader_started) {
        atomic_store(&capture->stop, 1);
        pthread_join(scope->reader, NULL);
    }
    for (unsigned stream = 0; stream < 2; ++stream) {
        if (scope->pipes[stream][0] >= 0) close(scope->pipes[stream][0]);
    }
}

/* Returns one when an explicit-exit callback already owns completion. */
static int capture_module(struct task_context *task)
{
    const struct job_request *request = task->request;
    struct job_result *result = task->result;
    struct capture_state *capture = &result->capture;
    struct capture_scope *scope = &task->scope;
    *scope = (struct capture_scope){.pipes = {{-1, -1}, {-1, -1}}, .saved = {-1, -1},
                                   .stdin_pair = {-1, -1}, .saved_stdin = -1};
    capture->max = request->max_capture;
    capture->read_fd[0] = capture->read_fd[1] = -1;
    capture->data[0] = malloc(capture->max);
    capture->data[1] = malloc(capture->max);
    int status = -EIO;
    int exit_code = 0;
    if (!capture->data[0] || !capture->data[1]) { status = -ENOMEM; goto complete; }
    if (pipe(scope->pipes[0]) || pipe(scope->pipes[1])) goto complete;
    for (unsigned stream = 0; stream < 2; ++stream) {
        int flags = fcntl(scope->pipes[stream][0], F_GETFL);
        if (flags < 0 || fcntl(scope->pipes[stream][0], F_SETFL, flags | O_NONBLOCK)) goto complete;
        capture->read_fd[stream] = scope->pipes[stream][0];
        scope->saved[stream] = dup((int)stream + 1);
        if (scope->saved[stream] < 0) goto complete;
    }
    fflush(NULL);
    if (pthread_create(&scope->reader, NULL, capture_reader, capture)) goto complete;
    scope->reader_started = 1;
    if (request->stdin_present) {
        if (pipe(scope->stdin_pair)) goto complete;
        int flags = fcntl(scope->stdin_pair[1], F_GETFL);
        if (flags < 0 || fcntl(scope->stdin_pair[1], F_SETFL, flags | O_NONBLOCK)) goto complete;
        scope->saved_stdin = dup(STDIN_FILENO);
        if (scope->saved_stdin < 0 || dup2(scope->stdin_pair[0], STDIN_FILENO) < 0) goto complete;
        scope->input.writer = scope->stdin_pair[1];
        scope->input.data = request->stdin_data;
        scope->input.length = request->stdin_length;
        if (pthread_create(&scope->feeder, NULL, feed_stdin, &scope->input)) goto complete;
        scope->stdin_started = 1;
    }
    for (unsigned stream = 0; stream < 2; ++stream) {
        if (dup2(scope->pipes[stream][1], (int)stream + 1) < 0) goto complete;
        ++scope->redirected;
        close(scope->pipes[stream][1]);
        scope->pipes[stream][1] = -1;
    }
    status = osv_sandbox_register_exit_callback(OSV_SANDBOX_EXIT_ABI, task_exit_callback, task);
    if (status) goto complete;
    // The callee only writes a local value; an exit callback may already be
    // completing the shared result on a different application thread.
    status = osv_sandbox_run_module(request->path, (const char *const *)request->argv,
                                    request->argc, &exit_code);
complete:
    if (!osc_completion_claim(&task->completion, (uintptr_t)pthread_self())) {
        wait_task_completion(task);
        return 1;
    }
    result->status = status;
    result->exit_code = exit_code;
    close_capture(task, 1);
    return 0;
}

static int send_result(int peer, const struct job_request *request,
                       const struct job_result *result)
{
    size_t length = RESULT_FIXED + result->capture.used[0] + result->capture.used[1];
    uint8_t *frame = malloc(length + 4);
    if (!frame) return -1;
    store32(frame, (uint32_t)length);
    uint8_t *body = frame + 4;
    memcpy(body, "OSJ1", 4);
    body[4] = 2;
    body[5] = (uint8_t)(result->capture.truncated[0] |
                        result->capture.truncated[1] << 1);
    body[6] = body[7] = 0;
    memcpy(body + 8, request->id, 24);
    memcpy(body + 32, request->nonce, 16);
    store32(body + 48, (uint32_t)result->status);
    store32(body + 52, (uint32_t)result->exit_code);
    store32(body + 56, (uint32_t)result->capture.used[0]);
    store32(body + 60, (uint32_t)result->capture.used[1]);
    if (result->capture.used[0])
        memcpy(body + 64, result->capture.data[0], result->capture.used[0]);
    if (result->capture.used[1])
        memcpy(body + 64 + result->capture.used[0], result->capture.data[1],
               result->capture.used[1]);
    int sent = send_all(peer, frame, length + 4);
    free(frame);
    return sent;
}

static int send_task_reply(struct task_context *task)
{
    if (send_result(task->peer, task->request, task->result)) return 0;
    uint8_t ack;
    return !receive_all(task->peer, &ack, 1) && ack == 0xa5;
}

static void task_exit_callback(void *opaque, int status)
{
    struct task_context *task = opaque;
    uintptr_t owner = (uintptr_t)pthread_self();
    if (!osc_completion_claim(&task->completion, owner)) {
        // Recursive exit from cleanup cannot wait for this same thread.
        if (!osc_completion_reentrant(&task->completion, owner)) wait_task_completion(task);
        return;
    }
    task->result->status = 0;
    task->result->exit_code = status;
    close_capture(task, 0);
    int complete = send_task_reply(task);
    if (complete) osv_vsock_shutdown(task->peer, 2);
    osv_vsock_close(task->peer);
    osv_vsock_close(task->listener);
    // main's request/response storage stays alive until this single-use VM
    // shuts down. A concurrently returning module may still hold its context.
    osc_completion_finish(&task->completion);
}

int main(int argc, char **argv)
{
    int pristine = osp_boot_mode(argc, argv);
    if (pristine < 0) {
        fputs("OSV_JOB_BOOT_REJECT invalid boot arguments\n", stderr);
        return 2;
    }
    struct osp_state state;
    if (pristine) {
        if (osp_init_revision(&state, monotonic_ms(), (unsigned)pristine)) return 2;
        atomic_store_explicit(&pristine_deadline, state.boot_deadline, memory_order_relaxed);
        pthread_t watchdog;
        if (pthread_create(&watchdog, NULL, pristine_watchdog, NULL)) return 2;
        pthread_detach(watchdog);
    }
    int listener = osv_vsock_listen(5000, 1);
    if (listener < 0) return 2;
    if (pristine) printf("OSV_PRISTINE_READY revision=%u\n", state.revision);
    else puts("OSV_JOB_READY");
    fflush(stdout);
    struct job_request request = {0};
    struct job_result result = {0};
    int peer = pristine ? wait_pristine_job(listener, &state, &request) :
        osv_vsock_accept(listener, 300000);
    struct task_context task = {.request = &request, .result = &result,
                                .peer = peer, .listener = listener};
    osc_completion_init(&task.completion);
    int complete = 0;
    if (peer >= 0 && (pristine || !read_request(peer, &request))) {
        task.completion_deadline = monotonic_ms() + request.timeout_ms + 1000u;
        uint64_t lease = atomic_load_explicit(&pristine_deadline, memory_order_relaxed);
        if (lease && lease < task.completion_deadline) task.completion_deadline = lease;
        atomic_store_explicit(&task_transfer_deadline, task.completion_deadline, memory_order_relaxed);
        int environment_ok = 1;
        for (unsigned index = 0; index < request.env_count; ++index) {
            if (setenv(request.env_names[index], request.env_values[index], 1)) {
                result.status = errno ? -errno : -EIO;
                environment_ok = 0;
                break;
            }
        }
        if (environment_ok && capture_module(&task)) shutdown_guest();
        complete = send_task_reply(&task);
    }
    free_request(&request);
    free(result.capture.data[0]);
    free(result.capture.data[1]);
    if (complete) osv_vsock_shutdown(peer, 2);
    if (peer >= 0) osv_vsock_close(peer);
    osv_vsock_close(listener);
    osc_completion_finish(&task.completion);
    shutdown_guest();
}
