#pragma once

#include <algorithm>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <memory>

namespace osv_sandbox {

// ROFS sectors are 512 bytes. A physically contiguous buffer keeps each block
// request representable by one data descriptor even when ordinary malloc has
// fallen back to a page-mapped allocation.
constexpr std::size_t rofs_sector_bytes = 512;
constexpr std::size_t rofs_max_read_bytes = 32 * 1024;

template <typename Allocate, typename Release, typename Read, typename Copy>
int bounded_rofs_read(std::uint64_t data_block, std::uint64_t file_size,
                      std::uint64_t offset, std::uint64_t requested,
                      Allocate allocate, Release release, Read read, Copy copy)
{
    if (!requested || offset >= file_size) {
        return 0;
    }
    auto remaining = std::min(requested, file_size - offset);
    const auto initial_offset = offset % rofs_sector_bytes;
    const auto first_copy = std::min<std::uint64_t>(remaining,
        rofs_max_read_bytes - initial_offset);
    const auto capacity = ((initial_offset + first_copy + rofs_sector_bytes - 1)
        / rofs_sector_bytes) * rofs_sector_bytes;
    std::unique_ptr<unsigned char, Release> buffer(
        static_cast<unsigned char*>(allocate(capacity)), release);
    if (!buffer) {
        return ENOMEM;
    }
    while (remaining) {
        const auto within = offset % rofs_sector_bytes;
        const auto count = std::min<std::uint64_t>(remaining, capacity - within);
        const auto sectors = (within + count + rofs_sector_bytes - 1) / rofs_sector_bytes;
        const auto relative_block = offset / rofs_sector_bytes;
        if (data_block > std::numeric_limits<std::uint64_t>::max() - relative_block) {
            return EINVAL;
        }
        const int error = read(data_block + relative_block, sectors, buffer.get());
        if (error) {
            return error;
        }
        const int moved = copy(buffer.get() + within, count);
        if (moved) {
            return moved;
        }
        offset += count;
        remaining -= count;
    }
    return 0;
}

} // namespace osv_sandbox
