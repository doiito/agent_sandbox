/* SPDX-License-Identifier: BSD-3-Clause */
#include "../osv-native/apps/job-agent/completion.h"
#include <assert.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>

static struct osc_completion completion;
static pthread_barrier_t start;
static atomic_uint winners;
static uintptr_t chosen_status;
static char payload[64];

static void *finish(void *argument)
{
    uintptr_t identity = (uintptr_t)argument;
    pthread_barrier_wait(&start);
    if (osc_completion_claim(&completion, identity)) {
        assert(osc_completion_reentrant(&completion, identity));
        assert(!osc_completion_reentrant(&completion, identity + 100));
        chosen_status = identity;
        strcpy(payload, "one response before ACK completion");
        atomic_fetch_add(&winners, 1);
        osc_completion_finish(&completion);
    } else {
        while (!osc_completion_done(&completion)) sched_yield();
    }
    assert(chosen_status && !strcmp(payload, "one response before ACK completion"));
    assert(!osc_completion_claim(&completion, identity));
    assert(!osc_completion_reentrant(&completion, identity));
    return NULL;
}

int main(void)
{
    osc_completion_init(&completion);
    assert(!osc_completion_done(&completion));
    assert(!osc_completion_reentrant(&completion, 1));
    assert(!pthread_barrier_init(&start, NULL, 32));
    pthread_t threads[32];
    for (uintptr_t i = 0; i < 32; ++i) assert(!pthread_create(&threads[i], NULL, finish, (void*)(i + 1)));
    for (unsigned i = 0; i < 32; ++i) assert(!pthread_join(threads[i], NULL));
    assert(atomic_load(&winners) == 1 && osc_completion_done(&completion));
    assert(atomic_load(&completion.owner) == chosen_status);
    assert(!pthread_barrier_destroy(&start));
    puts("TASK_COMPLETION_TEST_PASS contenders=32 response_winners=1 reentrant=detected");
}
