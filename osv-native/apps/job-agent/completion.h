/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef OSV_AGENT_COMPLETION_H
#define OSV_AGENT_COMPLETION_H

#include <stdatomic.h>
#include <stdint.h>

struct osc_completion {
    atomic_uint phase; /* 0 executing, 1 completing, 2 completed */
    atomic_uintptr_t owner;
};

static inline void osc_completion_init(struct osc_completion *state)
{
    atomic_init(&state->phase, 0);
    atomic_init(&state->owner, 0);
}

static inline int osc_completion_claim(struct osc_completion *state, uintptr_t owner)
{
    unsigned expected = 0;
    if (!atomic_compare_exchange_strong_explicit(&state->phase, &expected, 1,
                                                 memory_order_acq_rel, memory_order_acquire))
        return 0;
    atomic_store_explicit(&state->owner, owner, memory_order_release);
    return 1;
}

static inline int osc_completion_done(const struct osc_completion *state)
{
    return atomic_load_explicit(&state->phase, memory_order_acquire) == 2;
}

static inline int osc_completion_reentrant(const struct osc_completion *state, uintptr_t owner)
{
    return atomic_load_explicit(&state->phase, memory_order_acquire) == 1 &&
           atomic_load_explicit(&state->owner, memory_order_acquire) == owner;
}

static inline void osc_completion_finish(struct osc_completion *state)
{
    atomic_store_explicit(&state->phase, 2, memory_order_release);
}
#endif
