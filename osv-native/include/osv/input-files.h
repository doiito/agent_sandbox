/* SPDX-License-Identifier: BSD-3-Clause
 * Bounded OSP2 input decoder shared by the guest agent and kernel importer.
 */
#ifndef OSV_SANDBOX_INPUT_FILES_V1_H
#define OSV_SANDBOX_INPUT_FILES_V1_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define OSV_INPUT_MAX_FILES 64u
#define OSV_INPUT_MAX_PATH 1024u
#define OSV_INPUT_MAX_PATH_BYTES 32768u
#define OSV_INPUT_MAX_DATA_BYTES 524288u
#define OSV_INPUT_MAX_SUFFIX (4u + OSV_INPUT_MAX_FILES * 8u + OSV_INPUT_MAX_PATH_BYTES + OSV_INPUT_MAX_DATA_BYTES)

struct osv_input_view {
    const uint8_t *path;
    uint16_t path_length;
    const uint8_t *data;
    uint32_t data_length;
};

static inline uint16_t osv_input_u16(const uint8_t *p)
{
    return (uint16_t)p[0] | (uint16_t)p[1] << 8;
}

static inline uint32_t osv_input_u32(const uint8_t *p)
{
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

/* Match Go's utf8.ValidString/unicode.IsControl policy, including C1 controls. */
static inline int osv_input_text(const uint8_t *p, size_t size)
{
    for (size_t i = 0; i < size;) {
        uint32_t cp = p[i++];
        unsigned more = 0;
        uint32_t minimum = 0;
        if (cp >= 0xc2 && cp <= 0xdf) { more = 1; minimum = 0x80; cp &= 0x1f; }
        else if (cp >= 0xe0 && cp <= 0xef) { more = 2; minimum = 0x800; cp &= 0x0f; }
        else if (cp >= 0xf0 && cp <= 0xf4) { more = 3; minimum = 0x10000; cp &= 7; }
        else if (cp >= 0x80) return -1;
        if (more > size - i) return -1;
        for (unsigned n = 0; n < more; ++n) {
            uint8_t ch = p[i++];
            if ((ch & 0xc0) != 0x80) return -1;
            cp = cp << 6 | (ch & 0x3f);
        }
        if (more && cp < minimum) return -1;
        if (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) || cp < 0x20 ||
            (cp >= 0x7f && cp <= 0x9f)) return -1;
    }
    return 0;
}

static inline int osv_input_path(const uint8_t *p, size_t size)
{
    if (!size || size > OSV_INPUT_MAX_PATH || osv_input_text(p, size)) return -1;
    size_t start = 0;
    unsigned segments = 0;
    for (size_t i = 0; i <= size; ++i) {
        if (i < size && p[i] == '\\') return -1;
        if (i < size && p[i] != '/') continue;
        size_t length = i - start;
        if (!length || length > 255 || ++segments > 16 ||
            (length == 1 && p[start] == '.') ||
            (length == 2 && p[start] == '.' && p[start + 1] == '.')) return -1;
        start = i + 1;
    }
    return 0;
}

/* Decode only the suffix after the original 52-byte OSP binding/TTL header.
 * Views borrow the frame until the kernel has copied the complete input tree.
 * count stays zero on every failure; no filesystem or prepared state is changed.
 */
static inline int osv_input_decode(const uint8_t *body, size_t size,
                                    struct osv_input_view files[OSV_INPUT_MAX_FILES],
                                    size_t *count)
{
    if (!count) return -1;
    *count = 0;
    if (!body || !files || size < 4 || size > OSV_INPUT_MAX_SUFFIX || body[2] || body[3]) return -1;
    unsigned total = osv_input_u16(body);
    if (total > OSV_INPUT_MAX_FILES) return -1;
    size_t cursor = 4, paths = 0, bytes = 0;
    for (unsigned i = 0; i < total; ++i) {
        if (size - cursor < 8) return -1;
        uint16_t path_length = osv_input_u16(body + cursor);
        uint16_t reserved = osv_input_u16(body + cursor + 2);
        uint32_t data_length = osv_input_u32(body + cursor + 4);
        cursor += 8;
        if (reserved || path_length > OSV_INPUT_MAX_PATH_BYTES - paths ||
            data_length > OSV_INPUT_MAX_DATA_BYTES - bytes || path_length > size - cursor) return -1;
        const uint8_t *path = body + cursor;
        if (osv_input_path(path, path_length)) return -1;
        cursor += path_length;
        if (data_length > size - cursor) return -1;
        for (unsigned j = 0; j < i; ++j) {
            size_t previous = files[j].path_length;
            size_t shorter = previous < path_length ? previous : path_length;
            if (!memcmp(path, files[j].path, shorter) &&
                (previous == path_length || (previous < path_length && path[previous] == '/') ||
                 (path_length < previous && files[j].path[path_length] == '/'))) return -1;
        }
        files[i].path = path;
        files[i].path_length = path_length;
        files[i].data = body + cursor;
        files[i].data_length = data_length;
        cursor += data_length;
        paths += path_length;
        bytes += data_length;
    }
    if (cursor != size) return -1;
    *count = total;
    return 0;
}

#endif
