/* SPDX-License-Identifier: BSD-3-Clause */
/* Diagnostic transport peer. This is not the product agent. */
#include <osv/vsock.h>
#include <osv/sandbox-run.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_ECHO (1024u * 1024u)
#define PARALLEL_PEERS 8u
#define PARALLEL_CHUNKS 16u
#define PARALLEL_CHUNK_SIZE 4096u


static int receive_all(int handle, void *buffer, size_t size)
{
    uint8_t *p = buffer;
    while (size) {
        int64_t n = osv_vsock_recv(handle, p, size, 30000);
        if (n <= 0) return -1;
        p += n;
        size -= (size_t)n;
    }
    return 0;
}

static int send_all(int handle, const void *buffer, size_t size)
{
    const uint8_t *p = buffer;
    while (size) {
        int64_t n = osv_vsock_send(handle, p, size, 30000);
        if (n <= 0) return -1;
        p += n;
        size -= (size_t)n;
    }
    return 0;
}

static uint32_t load32(const uint8_t p[4])
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
        (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static void store32(uint8_t p[4], uint32_t n)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(n >> (8 * i));
}

struct parallel_job {
    unsigned index;
    int success;
};

static void *parallel_peer(void *argument)
{
    struct parallel_job *job = argument;
    int peer = osv_vsock_connect(2, 6001, 30000);
    if (peer < 0) return NULL;
    uint8_t index = (uint8_t)job->index;
    uint8_t gate = 0;
    uint8_t payload[PARALLEL_CHUNK_SIZE];
    int failed = send_all(peer, &index, 1) ||
        receive_all(peer, &gate, 1) || gate != 'G';
    for (unsigned chunk = 0; !failed && chunk < PARALLEL_CHUNKS; ++chunk) {
        for (unsigned offset = 0; offset < sizeof(payload); ++offset)
            payload[offset] = (uint8_t)(index * 17u + chunk * 13u + offset);
        failed = send_all(peer, payload, sizeof(payload));
    }
    uint8_t acknowledged = 0;
    if (!failed) failed = receive_all(peer, &acknowledged, 1) || acknowledged != index;
    if (osv_vsock_close(peer)) failed = 1;
    job->success = !failed;
    return NULL;
}

static int run_parallel(int handle)
{
    pthread_t threads[PARALLEL_PEERS];
    struct parallel_job jobs[PARALLEL_PEERS] = {{0}};
    unsigned created = 0;
    for (; created < PARALLEL_PEERS; ++created) {
        jobs[created].index = created;
        if (pthread_create(&threads[created], NULL, parallel_peer, &jobs[created])) break;
    }
    int failed = created != PARALLEL_PEERS;
    for (unsigned index = 0; index < created; ++index) {
        if (pthread_join(threads[index], NULL) || !jobs[index].success) failed = 1;
    }
    return failed ? -1 : send_all(handle, "parallel-ok", 11);
}

static int serve(int handle)
{
    uint8_t op;
    if (receive_all(handle, &op, 1)) return -1;
    if (op == 1) {
        uint8_t size_bytes[4];
        if (receive_all(handle, size_bytes, 4)) return -1;
        uint32_t size = load32(size_bytes);
        if (size > MAX_ECHO) return -1;
        uint8_t *payload = malloc(size ? size : 1);
        if (!payload) return -1;
        int result = receive_all(handle, payload, size) ||
            send_all(handle, size_bytes, 4) || send_all(handle, payload, size);
        free(payload);
        return result ? -1 : 0;
    }
    if (op == 2) {
        static const char reply[] = "half";
        if (send_all(handle, reply, sizeof(reply) - 1) ||
            osv_vsock_shutdown(handle, 2)) return -1;
        return 0;
    }
    if (op == 3) {
        int guest = osv_vsock_connect(2, 6000, 30000);
        if (guest < 0) return -1;
        static const char request[] = "guest";
        char response[4];
        int result = send_all(guest, request, sizeof(request) - 1) ||
            receive_all(guest, response, sizeof(response)) ||
            response[0] != 'h' || response[1] != 'o' ||
            response[2] != 's' || response[3] != 't';
        osv_vsock_close(guest);
        return result || send_all(handle, "connected", 9) ? -1 : 0;
    }
    if (op == 4) {
        int result = osv_vsock_connect(2, 6010, 30000);
        uint8_t reply[4];
        store32(reply, (uint32_t)result);
        if (result >= 0) osv_vsock_close(result);
        return send_all(handle, reply, 4);
    }
    if (op == 5) {
        uint8_t byte;
        int64_t result = osv_vsock_recv(handle, &byte, 1, 20);
        uint8_t reply[4];
        store32(reply, (uint32_t)result);
        return send_all(handle, reply, 4);
    }
    if (op == 6) {
        char byte;
        if (receive_all(handle, &byte, 1) || byte != 'Z' ||
            osv_vsock_recv(handle, &byte, 1, 30000) != 0) return -1;
        puts("VSOCK_HOST_EOF_OK");
        fflush(stdout);
        return 0;
    }
    if (op == 7) return run_parallel(handle);
    if (op == 8) {
        uint8_t length;
        if (receive_all(handle, &length, 1) || !length || length > 32) return -1;
        char argument[33];
        if (receive_all(handle, argument, length)) return -1;
        argument[length] = '\0';
        const char *argv[] = {"/task-probe.so", argument};
        int result = 0;
        int status = osv_sandbox_run_module(argv[0], argv, 2, &result);
        uint8_t reply[4];
        store32(reply, (uint32_t)(status ? status : result));
        return send_all(handle, reply, sizeof(reply));
    }
    if (op == 9 || op == 10) {
        const char *path = op == 9 ? "/missing.so" : "/../task-probe.so";
        const char *argv[] = {path};
        int result = 0;
        int status = osv_sandbox_run_module(path, argv, 1, &result);
        uint8_t reply[4];
        store32(reply, (uint32_t)status);
        return send_all(handle, reply, sizeof(reply));
    }
    if (op == 99) {
        uint8_t ack;
        if (send_all(handle, "done", 4)) return -1;
        return receive_all(handle, &ack, 1) || ack != 0xa5 ? -1 : 1;
    }
    return -1;
}

int main(void)
{
    if (osv_vsock_cid() <= 2) return 2;
    int listener = osv_vsock_listen(5000, 8);
    if (listener < 0) return 3;
    if (osv_vsock_listen(5000, 8) != -EADDRINUSE ||
        osv_vsock_accept(listener, 0) != -EAGAIN ||
        osv_vsock_accept(listener, 20) != -ETIMEDOUT) return 4;
    puts("VSOCK_READY");
    fflush(stdout);
    for (;;) {
        int peer = osv_vsock_accept(listener, 300000);
        if (peer < 0) return 5;
        int result = serve(peer);
        osv_vsock_close(peer);
        if (result < 0) return 6;
        if (result == 1) break;
    }
    osv_vsock_close(listener);
    puts("VSOCK_DONE");
    fflush(stdout);
    return 0;
}
