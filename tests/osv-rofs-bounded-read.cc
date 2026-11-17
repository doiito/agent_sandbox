#include "../osv-native/fs/rofs/bounded-read.hh"
#include <cassert>
#include <cstdlib>
#include <cstring>
#include <vector>

struct fixture {
    std::vector<unsigned char> disk;
    std::vector<unsigned char> copied;
    unsigned allocations = 0, releases = 0, reads = 0, copies = 0;
    unsigned fail_read = 0;
    bool fail_alloc = false, fail_copy = false;
    std::size_t allocated = 0;
    fixture() : disk(3 * 1024 * 1024) {
        for (std::size_t i = 0; i < disk.size(); ++i) disk[i] = (i * 71 + i / 257) & 255;
    }
    int run(std::uint64_t size, std::uint64_t offset, std::uint64_t count) {
        return osv_sandbox::bounded_rofs_read(0, size, offset, count,
            [this](std::size_t length) -> void* {
                ++allocations;
                allocated = length;
                assert(length && length <= 32768 && length % 512 == 0);
                if (fail_alloc) return nullptr;
                void* buffer = nullptr;
                assert(posix_memalign(&buffer, 4096, length) == 0);
                std::memset(buffer, 0xa5, length);
                return buffer;
            },
            [this](void* buffer) { ++releases; std::free(buffer); },
            [this](std::uint64_t block, std::uint64_t sectors, void* buffer) {
                ++reads;
                assert(reinterpret_cast<std::uintptr_t>(buffer) % 4096 == 0);
                assert(sectors && sectors * 512 <= allocated);
                assert(block * 512 + sectors * 512 <= disk.size());
                if (reads == fail_read) {
                    std::memset(buffer, 0, sectors * 512);
                    return EIO;
                }
                std::memcpy(buffer, disk.data() + block * 512, sectors * 512);
                return 0;
            },
            [this](void* buffer, std::size_t length) {
                ++copies;
                if (fail_copy) return EFAULT;
                auto bytes = static_cast<unsigned char*>(buffer);
                copied.insert(copied.end(), bytes, bytes + length);
                return 0;
            });
    }
};

int main() {
    for (std::uint64_t offset : {0, 1, 511, 512, 4095, 32767, 32768, 65537, 100002}) {
        for (std::uint64_t count : {1, 513, 32768, 99999}) {
            fixture f;
            assert(f.run(100003, offset, count) == 0);
            auto length = std::min<std::uint64_t>(count, 100003 - offset);
            assert(f.copied == std::vector<unsigned char>(f.disk.begin() + offset, f.disk.begin() + offset + length));
            assert(f.allocations == 1 && f.releases == 1 && f.reads == f.copies);
        }
    }
    {
        fixture f;
        assert(f.run(100003, 0, 0) == 0 && f.run(100003, 100003, 42) == 0);
        assert(f.allocations == 0 && f.reads == 0 && f.copies == 0);
    }
    {
        fixture f;
        f.fail_alloc = true;
        assert(f.run(100003, 0, 99) == ENOMEM);
        assert(f.allocations == 1 && f.releases == 0 && f.reads == 0 && f.copies == 0);
    }
    {
        fixture f;
        f.fail_read = 3;
        assert(f.run(100003, 17, 100000) == EIO);
        assert(f.reads == 3 && f.copies == 2 && f.releases == 1);
        assert(f.copied == std::vector<unsigned char>(f.disk.begin() + 17, f.disk.begin() + 65536));
    }
    {
        fixture f;
        f.fail_copy = true;
        assert(f.run(100003, 511, 8192) == EFAULT);
        assert(f.reads == 1 && f.copies == 1 && f.copied.empty() && f.releases == 1);
    }
    {
        fixture f;
        assert(f.run(f.disk.size(), 0, 2 * 1024 * 1024 - 512) == 0);
        assert(f.copied == std::vector<unsigned char>(f.disk.begin(), f.disk.begin() + 2 * 1024 * 1024 - 512));
        assert(f.allocations == 1 && f.releases == 1 && f.reads > 1);
    }
}
