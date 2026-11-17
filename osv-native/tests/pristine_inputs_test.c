/* SPDX-License-Identifier: BSD-3-Clause */
#include "../apps/job-agent/pristine-inputs.h"
#include <assert.h>
#include <stdio.h>

struct mount_fixture {
    unsigned calls;
    int fail;
    uint64_t now;
};

static int mount_inputs(const struct osv_input_view *files, size_t count, void *opaque)
{
    struct mount_fixture *fixture = opaque;
    ++fixture->calls;
    assert(count == 1 && files[0].path_length == 1 && files[0].path[0] == 'x');
    assert(files[0].data_length == 4 && !memcmp(files[0].data, "A\0\xff\n", 4));
    return fixture->fail;
}

static uint64_t now(void *opaque)
{
    return ((struct mount_fixture *)opaque)->now;
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    char *boot[] = {"/osv-job-agent.so", "--pristine-inputs-v1", "pci=off", "root=/dev/vda", "ro"};
    assert(osp_boot_mode(5, boot) == 2);
    struct osp_state state;
    assert(osp_init_revision(&state, 1000, 3) == -1);
    assert(osp_init_revision(&state, 1000, 2) == 0);
    uint8_t prepare[69] = {0}, response[OSP_RESPONSE_SIZE], expected[OSP_RESPONSE_SIZE];
    FILE *vectors = fopen(argv[1], "r");
    assert(vectors);
    for (size_t i = 0; i < sizeof(prepare); ++i) {
        unsigned value;
        assert(fscanf(vectors, "%2x", &value) == 1);
        prepare[i] = (uint8_t)value;
    }
    for (size_t i = 0; i < sizeof(expected); ++i) {
        unsigned value;
        assert(fscanf(vectors, "%2x", &value) == 1);
        expected[i] = (uint8_t)value;
    }
    fclose(vectors);

    struct mount_fixture fixture = {.now = 1007};
    for (size_t length = 0; length < sizeof(prepare); ++length) {
        struct osp_state before = state;
        assert(osp_control_transaction(&state, prepare, length, 1000, response, mount_inputs, now, &fixture) == -1);
        assert(!memcmp(&state, &before, sizeof(state)) && fixture.calls == 0);
    }
    fixture.fail = 1;
    struct osp_state before = state;
    assert(osp_control_transaction(&state, prepare, sizeof(prepare), 1000, response, mount_inputs, now, &fixture) == -1);
    assert(!memcmp(&state, &before, sizeof(state)) && fixture.calls == 1);
    fixture.fail = 0;
    fixture.now = 2000;
    assert(osp_control_transaction(&state, prepare, sizeof(prepare), 1000, response, mount_inputs, now, &fixture) == -1);
    assert(!memcmp(&state, &before, sizeof(state)) && fixture.calls == 2);
    fixture.now = 1007;
    assert(osp_control_transaction(&state, prepare, sizeof(prepare), 1000, response, NULL, now, &fixture) == -1);
    assert(!memcmp(&state, &before, sizeof(state)) && fixture.calls == 2);
    assert(osp_control_transaction(&state, prepare, sizeof(prepare), 1000, response, mount_inputs, now, &fixture) == 0);
    assert(state.prepared == 1 && state.revision == 2 && fixture.calls == 3);
    assert(!memcmp(response, expected, sizeof(response)));
    assert(!memcmp(response, "OSP2", 4) && osp_load32(response + 48) == 2 && osp_load32(response + 56) == 993);
    assert(osp_control_transaction(&state, prepare, sizeof(prepare), 1008, response, mount_inputs, now, &fixture) == -1);
    assert(fixture.calls == 3);
    uint8_t job[48];
    memcpy(job, prepare, sizeof(job));memcpy(job, "OSJ1", 4);job[4] = 1;
    assert(osp_consume_job(&state, job, sizeof(job), 1008) == 0);
    assert(osp_consume_job(&state, job, sizeof(job), 1009) == -1);

    assert(osp_init(&state, 1000) == 0);
    assert(osp_control_transaction(&state, prepare, sizeof(prepare), 1000, response, mount_inputs, now, &fixture) == -1);
    memcpy(prepare, "OSP1", 4);
    assert(osp_control_transaction(&state, prepare, OSP_REQUEST_SIZE, 1000, response, NULL, now, &fixture) == 0);
    assert(state.prepared == 1 && state.revision == 1 && fixture.calls == 3);
    puts("OSv OSP2 mount-before-binding, expiry, version and one-use checks passed");
    return 0;
}
