/* SPDX-License-Identifier: BSD-3-Clause */
#include "../apps/job-agent/pristine.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

static void read_vector(FILE *input, uint8_t *output, size_t length)
{
    for (size_t i = 0; i < length; ++i) {
        unsigned value;
        assert(fscanf(input, "%2x", &value) == 1);
        output[i] = (uint8_t)value;
    }
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    char *plain[] = {"/osv-job-agent.so"};
    char *pristine[] = {"/osv-job-agent.so", "--pristine-v1"};
    char *fc_plain[] = {"/osv-job-agent.so", "pci=off", "root=/dev/vda", "ro"};
    char *fc_pristine[] = {"/osv-job-agent.so", "--pristine-v1", "pci=off", "root=/dev/vda", "ro"};
    assert(osp_boot_mode(1, plain) == 0);
    assert(osp_boot_mode(2, pristine) == 1);
    assert(osp_boot_mode(4, fc_plain) == 0);
    assert(osp_boot_mode(5, fc_pristine) == 1);
    fc_pristine[3] = "root=/dev/vdb";
    assert(osp_boot_mode(5, fc_pristine) == -1);
    assert(osp_boot_mode(2, fc_pristine + 1) == -1);
    pristine[1] = "--pristine-v2";
    assert(osp_boot_mode(2, pristine) == -1);
    FILE *vectors = fopen(argv[1], "r");
    assert(vectors);
    uint8_t ping[OSP_REQUEST_SIZE], expected[OSP_RESPONSE_SIZE], response[OSP_RESPONSE_SIZE];
    read_vector(vectors, ping, sizeof(ping));
    read_vector(vectors, expected, sizeof(expected));
    fclose(vectors);
    struct osp_state state;
    assert(osp_init(&state, 0) == -1);
    assert(osp_init(&state, UINT64_MAX - 100) == -1);
    assert(osp_init(&state, 1000) == 0);
    assert(osp_control(&state, ping, sizeof(ping), 1000, response) == 0);
    assert(!memcmp(response, expected, sizeof(response)));
    for (unsigned i = 1; i < OSP_MAX_CHECKS; ++i)
        assert(osp_control(&state, ping, sizeof(ping), 1000, response) == 0);
    assert(state.prepared == 0 && state.checks == OSP_MAX_CHECKS);
    assert(osp_control(&state, ping, sizeof(ping), 1000, response) == -1);

    uint8_t prepare[OSP_REQUEST_SIZE];
    memcpy(prepare, ping, sizeof(prepare));
    prepare[4] = 3;
    osp_store32(prepare + 48, 1500);
    assert(osp_control(&state, prepare, sizeof(prepare), 1000, response) == 0);
    assert(state.prepared == 1 && state.lease_deadline == 2500);
    assert(response[4] == 4 && osp_load32(response + 52) == 1);
    assert(osp_load32(response + 56) == 1500);
    assert(osp_control(&state, prepare, sizeof(prepare), 1001, response) == -1);
    assert(osp_control(&state, ping, sizeof(ping), 1001, response) == -1);
    assert(osp_remaining(&state, 2499) == 1);
    assert(osp_remaining(&state, 2500) == 0);
    assert(osp_remaining(&state, 0) == 0);

    uint8_t job[48];
    memcpy(job, ping, sizeof(job));
    memcpy(job, "OSJ1", 4);
    struct osp_state bound = state;
    for (unsigned i = 0; i < sizeof(job); ++i) {
        uint8_t bad[48];
        memcpy(bad, job, sizeof(bad));
        bad[i] ^= 0x80;
        state = bound;
        assert(osp_consume_job(&state, bad, sizeof(bad), 1001) == -1);
    }
    state = bound;
    assert(osp_consume_job(&state, job, sizeof(job), 2500) == -1);
    assert(osp_consume_job(&state, job, sizeof(job), 1001) == 0);
    assert(state.prepared == 2 && osp_remaining(&state, 2499) == 1);
    assert(osp_consume_job(&state, job, sizeof(job), 1002) == -1);

    for (unsigned i = 0; i < sizeof(ping); ++i) {
        /* ID/nonce are challenges and may differ, reserved bits/TTL may not. */
        if (i >= 8 && i < 48) continue;
        uint8_t bad[OSP_REQUEST_SIZE];
        memcpy(bad, ping, sizeof(bad));
        bad[i] ^= 0x80;
        assert(osp_init(&state, 1000) == 0);
        assert(osp_control(&state, bad, sizeof(bad), 1001, response) == -1);
    }
    for (size_t length = 0; length < sizeof(ping); ++length) {
        assert(osp_init(&state, 1000) == 0);
        assert(osp_control(&state, ping, length, 1001, response) == -1);
    }
    assert(osp_init(&state, 1000) == 0);
    assert(osp_control(&state, NULL, 0, 1001, response) == -1);
    assert(osp_control(&state, ping, sizeof(ping) + 1, 1001, response) == -1);
    assert(osp_control(&state, ping, sizeof(ping), 601000, response) == -1);
    assert(osp_consume_job(&state, job, sizeof(job), 1001) == -1);
    assert(osp_control(&state, prepare, sizeof(prepare), 594500, response) == -1);
    assert(osp_control(&state, prepare, sizeof(prepare), 594499, response) == 0);
    assert(state.lease_deadline < state.boot_deadline);
    puts("OSv pristine codec, binding, one-use and lifetime checks passed");
    return 0;
}
