/* SPDX-License-Identifier: BSD-3-Clause */
#include "../osv-native/libc/pipe-stat.hh"
#include <algorithm>
#include <cassert>
#include <iostream>
#include <memory>
#include <thread>
#include <vector>

int main()
{
    using namespace osv_sandbox;
    pipe_inode_allocator ids;
    std::vector<std::vector<ino_t>> values(8);
    std::vector<std::thread> workers;
    for (auto& thread_values : values) {
        workers.emplace_back([&ids, &thread_values] {
            for (unsigned i = 0; i < 2048; ++i) {
                ino_t id = 0;
                assert(ids.allocate(id));
                thread_values.push_back(id);
            }
        });
    }
    for (auto& worker : workers) worker.join();
    std::vector<ino_t> merged;
    for (const auto& thread_values : values)
        merged.insert(merged.end(), thread_values.begin(), thread_values.end());
    std::sort(merged.begin(), merged.end());
    for (size_t i = 0; i < merged.size(); ++i) assert(merged[i] == i + 1);

    pipe_inode_allocator ending(std::numeric_limits<ino_t>::max() - 1);
    ino_t id = 42;
    assert(ending.allocate(id) && id == std::numeric_limits<ino_t>::max() - 1);
    id = 42;
    for (unsigned i = 0; i < 128; ++i) assert(!ending.allocate(id) && id == 42);
    pipe_inode_allocator zero(0);
    assert(!zero.allocate(id) && id == 42);

    const timespec created{1793538838, 123456789};
    auto first = std::make_shared<const pipe_stat_metadata>(123, 234, 345, created);
    auto other_end = first;
    struct stat read_end, write_end, expected;
    std::memset(&read_end, 0xa5, sizeof(read_end));
    std::memset(&write_end, 0x5a, sizeof(write_end));
    first->copy_to(&read_end);
    other_end->copy_to(&write_end);
    assert(std::memcmp(&read_end, &write_end, sizeof(read_end)) == 0);
    assert(read_end.st_ino == 123 && read_end.st_uid == 234 && read_end.st_gid == 345);
    assert(S_ISFIFO(read_end.st_mode) && (read_end.st_mode & 0777) == 0600);
    assert(read_end.st_dev == static_cast<dev_t>(-1) && read_end.st_nlink == 1);
    assert(read_end.st_size == 0 && read_end.st_blocks == 0 && read_end.st_blksize == 4096);
    assert(read_end.st_atim.tv_sec == created.tv_sec && read_end.st_atim.tv_nsec == created.tv_nsec);
    assert(read_end.st_mtim.tv_sec == created.tv_sec && read_end.st_ctim.tv_nsec == created.tv_nsec);
    // Zero every specified field: remaining reserved/padding bytes must be zero.
    expected = read_end;
    expected.st_dev = 0; expected.st_ino = 0; expected.st_mode = 0; expected.st_nlink = 0;
    expected.st_uid = 0; expected.st_gid = 0; expected.st_blksize = 0;
    expected.st_atim = {}; expected.st_mtim = {}; expected.st_ctim = {};
    unsigned char empty[sizeof(expected)]{};
    assert(std::memcmp(&expected, empty, sizeof(expected)) == 0);
    first.reset();
    other_end->copy_to(&write_end);
    assert(write_end.st_ino == 123);
    workers.clear();
    for (unsigned i = 0; i < 8; ++i) {
        workers.emplace_back([other_end, &read_end] {
            for (unsigned n = 0; n < 4096; ++n) {
                struct stat snapshot;
                other_end->copy_to(&snapshot);
                assert(std::memcmp(&snapshot, &read_end, sizeof(snapshot)) == 0);
            }
        });
    }
    for (auto& worker : workers) worker.join();
    std::cout << "PIPE_METADATA_TEST_PASS concurrent=16384 saturation=128 immutable=32768 padding=zero\n";
}
