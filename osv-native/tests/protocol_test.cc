// SPDX-License-Identifier: BSD-3-Clause
#include "../drivers/vsock-protocol.hh"
#include <cassert>
#include <iostream>
#include <random>
using namespace osv_vsock_protocol;

int main() {
    std::array<uint8_t, header_size+max_payload> buffer{};
    header original;
    original.src_cid=0x01020304; original.dst_cid=3;
    original.src_port=0x40000001; original.dst_port=5000; original.op=data; original.length=17;
    encode(original,buffer.data());
    assert(buffer[0]==4 && buffer[3]==1 && buffer[16]==1 && buffer[19]==0x40);
    header parsed;
    assert(decode(buffer.data(),header_size+17,parsed));
    assert(parsed.src_cid==original.src_cid && parsed.src_port==original.src_port && parsed.length==17);
    for (size_t n=0;n<header_size;n++) assert(!decode(buffer.data(),n,parsed));
    assert(!decode(buffer.data(),header_size+16,parsed));
    assert(!decode(buffer.data(),header_size+max_payload+1,parsed));
    assert(valid_stream(original));
    original.flags=1;assert(!valid_stream(original));
    original.op=shutdown;original.length=0;assert(valid_stream(original));
    original.flags=4;assert(!valid_stream(original));

    credit_window credit;
    assert(credit.update(65536,0));assert(credit.reserve(65536));assert(!credit.reserve(1));
    assert(!credit.update(65536,65537));assert(credit.outstanding()==65536);
    assert(credit.update(65536,32768));assert(credit.available()==32768);
    assert(!credit.update(10,32768));
    credit.sent=0xfffffff0U;credit.peer_forwarded=0xffffffe0U;credit.peer_allocation=64;
    assert(credit.reserve(32));assert(credit.sent==16);assert(credit.outstanding()==48);
    assert(credit.update(64,0));assert(credit.available()==48);
    assert(!credit.update(max_peer_allocation+1,0));

    byte_ring ring(8);uint8_t bytes[]{0,1,2,3,4,5,6,7}, output[8]{};
    assert(ring.push(bytes,8));assert(!ring.push(bytes,1));assert(ring.pop(output,5)==5);
    assert(ring.push(bytes,5));assert(ring.pop(output,8)==8);
    assert(output[0]==5 && output[2]==7 && output[3]==0 && output[7]==4);

    // Deterministic parser fuzz/property corpus; ASan/UBSan verify bounds.
    std::mt19937 random(0x5a17);
    for (unsigned iteration=0;iteration<100000;++iteration) {
        size_t size=random()%(buffer.size()+1);
        for (size_t i=0;i<std::min(size,header_size);++i) buffer[i]=uint8_t(random());
        if (decode(buffer.data(),size,parsed)) {
            assert(parsed.length==size-header_size && parsed.length<=max_payload);
        }
        credit_window window;
        window.peer_allocation=random()%65537;
        uint32_t amount=random()%100000;
        const bool accepted=window.reserve(amount);
        assert(accepted==(amount<=window.peer_allocation));
        assert(window.outstanding()<=window.peer_allocation);
    }
    std::cout << "vsock codec/credit/ring: passed; 100000 deterministic property cases\n";
}
