/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef OSV_SANDBOX_VSOCK_PROTOCOL_HH
#define OSV_SANDBOX_VSOCK_PROTOCOL_HH

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <vector>

namespace osv_vsock_protocol {
constexpr size_t header_size = 44;
constexpr size_t max_payload = 4096;
constexpr uint32_t receive_capacity = 65536;
constexpr uint32_t max_peer_allocation = 16 * 1024 * 1024;
constexpr uint64_t host_cid = 2;
enum operation : uint16_t { request = 1, response = 2, reset = 3, shutdown = 4,
    data = 5, credit_update = 6, credit_request = 7 };
constexpr uint32_t no_receive = 1;
constexpr uint32_t no_send = 2;

struct header {
    uint64_t src_cid = 0, dst_cid = 0;
    uint32_t src_port = 0, dst_port = 0, length = 0;
    uint16_t type = 1, op = 0;
    uint32_t flags = 0, buf_alloc = receive_capacity, fwd_count = 0;
};

inline uint64_t load_le(const uint8_t* bytes, unsigned count) {
    uint64_t value = 0;
    for (unsigned i = 0; i < count; ++i) value |= uint64_t(bytes[i]) << (8 * i);
    return value;
}
inline void store_le(uint8_t* bytes, uint64_t value, unsigned count) {
    for (unsigned i = 0; i < count; ++i) bytes[i] = uint8_t(value >> (8 * i));
}
inline void encode(const header& h, uint8_t* bytes) {
    store_le(bytes, h.src_cid, 8); store_le(bytes+8, h.dst_cid, 8);
    store_le(bytes+16, h.src_port, 4); store_le(bytes+20, h.dst_port, 4);
    store_le(bytes+24, h.length, 4); store_le(bytes+28, h.type, 2);
    store_le(bytes+30, h.op, 2); store_le(bytes+32, h.flags, 4);
    store_le(bytes+36, h.buf_alloc, 4); store_le(bytes+40, h.fwd_count, 4);
}
inline bool decode(const void* buffer, size_t length, header& h) {
    if (length < header_size || length > header_size + max_payload) return false;
    const auto* bytes = static_cast<const uint8_t*>(buffer);
    h.src_cid = load_le(bytes, 8); h.dst_cid = load_le(bytes+8, 8);
    h.src_port = load_le(bytes+16, 4); h.dst_port = load_le(bytes+20, 4);
    h.length = load_le(bytes+24, 4); h.type = load_le(bytes+28, 2);
    h.op = load_le(bytes+30, 2); h.flags = load_le(bytes+32, 4);
    h.buf_alloc = load_le(bytes+36, 4); h.fwd_count = load_le(bytes+40, 4);
    return h.length == length-header_size;
}
inline bool valid_stream(const header& h) {
    if (h.type != 1 || h.op < request || h.op > credit_request) return false;
    if (h.op == shutdown) return h.length == 0 && h.flags != 0 && !(h.flags & ~uint32_t(3));
    return h.flags == 0 && (h.op == data || h.length == 0);
}

struct credit_window {
    uint32_t sent = 0, peer_forwarded = 0, peer_allocation = 0;
    uint32_t outstanding() const { return sent-peer_forwarded; }
    uint32_t available() const { return peer_allocation-outstanding(); }
    bool update(uint32_t allocation, uint32_t forwarded) {
        const uint32_t advance = forwarded-peer_forwarded;
        if (allocation > max_peer_allocation || advance > outstanding() || sent-forwarded > allocation) return false;
        peer_forwarded = forwarded;
        peer_allocation = allocation;
        return true;
    }
    bool reserve(uint32_t count) {
        if (count > available()) return false;
        sent += count;
        return true;
    }
};

class byte_ring {
    std::vector<uint8_t> bytes;
    size_t head = 0, count = 0;
public:
    explicit byte_ring(size_t capacity = receive_capacity) : bytes(capacity) {}
    size_t size() const { return count; }
    size_t room() const { return bytes.size()-count; }
    void clear() { head = count = 0; }
    bool push(const uint8_t* source, size_t length) {
        if (length > room()) return false;
        for (size_t i = 0; i < length; ++i) bytes[(head+count+i)%bytes.size()] = source[i];
        count += length;
        return true;
    }
    size_t pop(uint8_t* destination, size_t length) {
        length = std::min(length, count);
        for (size_t i = 0; i < length; ++i) destination[i] = bytes[(head+i)%bytes.size()];
        head = (head+length)%bytes.size(); count -= length;
        return length;
    }
};
}
#endif
