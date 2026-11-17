/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef OSV_AGENT_PRISTINE_H
#define OSV_AGENT_PRISTINE_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <osv/input-files.h>

#define OSP_REQUEST_SIZE 52u
#define OSP_RESPONSE_SIZE 64u
#define OSP_BOOT_LIFETIME_MS 600000u
#define OSP_MAX_CHECKS 6000u
#define OSP_INPUT_REQUEST_MAX (OSP_REQUEST_SIZE + OSV_INPUT_MAX_SUFFIX)

struct osp_state {
    uint64_t boot_deadline;
    uint64_t lease_deadline;
    uint32_t checks;
    unsigned prepared; /* 0 pristine, 1 bound, 2 execution consumed */
    unsigned revision;
    uint8_t binding[40]; /* ID[24], nonce[16]; never a tenant payload */
};

/* The pinned Firecracker appends Linux boot arguments after the OSv module.
 * Recognize only its exact fixed tail; all other application args stay strict. */
static inline int osp_boot_mode(int argc, char **argv)
{
    if (argc >= 4 && !strcmp(argv[argc - 3], "pci=off") &&
        !strcmp(argv[argc - 2], "root=/dev/vda") && !strcmp(argv[argc - 1], "ro"))
        argc -= 3;
    if (argc == 1) return 0;
    if (argc == 2 && !strcmp(argv[1], "--pristine-v1")) return 1;
    if (argc == 2 && !strcmp(argv[1], "--pristine-inputs-v1")) return 2;
    return -1;
}

static inline uint32_t osp_load32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 |
        (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

static inline void osp_store32(uint8_t *p, uint32_t value)
{
    for (unsigned i = 0; i < 4; ++i) p[i] = (uint8_t)(value >> (8 * i));
}

static inline int osp_init_revision(struct osp_state *state, uint64_t now, unsigned revision)
{
    memset(state, 0, sizeof(*state));
    if (!now || now > UINT64_MAX - OSP_BOOT_LIFETIME_MS || (revision != 1 && revision != 2)) return -1;
    state->boot_deadline = now + OSP_BOOT_LIFETIME_MS;
    state->revision = revision;
    return 0;
}

static inline int osp_init(struct osp_state *state, uint64_t now)
{
    return osp_init_revision(state, now, 1);
}

static inline uint32_t osp_remaining(const struct osp_state *state, uint64_t now)
{
    uint64_t deadline = state->prepared ? state->lease_deadline : state->boot_deadline;
    if (!now || !deadline || now >= deadline) return 0;
    uint64_t remaining = deadline - now;
    return remaining > OSP_BOOT_LIFETIME_MS ? 0 : (uint32_t)remaining;
}

static inline int osp_valid_identity(const uint8_t *body)
{
    for (unsigned i = 8; i < 32; ++i) {
        uint8_t ch = body[i];
        if (!((ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f'))) return 0;
    }
    unsigned nonzero = 0;
    for (unsigned i = 32; i < 48; ++i) nonzero |= body[i];
    return nonzero != 0;
}

/* Caller terminates the VM on every failure; no failed operation is retried. */
static inline int osp_control(struct osp_state *state, const uint8_t *body,
                              size_t length, uint64_t now,
                              uint8_t response[OSP_RESPONSE_SIZE])
{
    uint32_t remaining = osp_remaining(state, now);
    const int inputs = state->revision == 2;
    if ((state->revision != 1 && !inputs) || state->prepared || !remaining || length < OSP_REQUEST_SIZE ||
        length > (inputs ? OSP_INPUT_REQUEST_MAX : OSP_REQUEST_SIZE) ||
        memcmp(body, inputs ? "OSP2" : "OSP1", 4) || body[5] || body[6] || body[7] ||
        !osp_valid_identity(body)) return -1;
    uint32_t ttl = osp_load32(body + 48);
    if (body[4] == 1) {
        if (ttl || length != OSP_REQUEST_SIZE || state->checks >= OSP_MAX_CHECKS) return -1;
        ++state->checks;
    } else if (body[4] == 3) {
        if (ttl < 1000 || ttl > 300000 || remaining <= ttl + 5000) return -1;
        if (inputs) {
            struct osv_input_view files[OSV_INPUT_MAX_FILES];
            size_t count;
            if (length < OSP_REQUEST_SIZE + 4 ||
                osv_input_decode(body + OSP_REQUEST_SIZE, length - OSP_REQUEST_SIZE, files, &count)) return -1;
        }
        memcpy(state->binding, body + 8, sizeof(state->binding));
        state->lease_deadline = now + ttl; /* bounded by boot_deadline above */
        state->prepared = 1;
        remaining = ttl;
    } else {
        return -1;
    }
    memset(response, 0, OSP_RESPONSE_SIZE);
    memcpy(response, body, 48);
    response[4] = body[4] + 1;
    osp_store32(response + 48, state->revision);
    osp_store32(response + 52, state->prepared);
    osp_store32(response + 56, remaining);
    return 0;
}

static inline int osp_consume_job(struct osp_state *state, const uint8_t *body,
                                  size_t length, uint64_t now)
{
    if (state->prepared != 1 || !osp_remaining(state, now) || length < 48 ||
        memcmp(body, "OSJ1", 4) || body[4] != 1 || (body[5] & ~3u) ||
        body[6] || body[7] || memcmp(body + 8, state->binding, sizeof(state->binding)))
        return -1;
    state->prepared = 2;
    return 0;
}

#endif
