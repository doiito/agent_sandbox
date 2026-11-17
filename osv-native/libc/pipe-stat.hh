/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef OSV_SANDBOX_PIPE_STAT_HH
#define OSV_SANDBOX_PIPE_STAT_HH

#include <atomic>
#include <cstring>
#include <limits>
#include <sys/stat.h>
#include <time.h>
#include <type_traits>

namespace osv_sandbox {

class pipe_inode_allocator {
    static_assert(std::is_unsigned<ino_t>::value, "pipe inode identifiers must be unsigned");
    std::atomic<ino_t> next_;
public:
    explicit constexpr pipe_inode_allocator(ino_t first = 1) noexcept : next_(first) {}

    bool allocate(ino_t& output) noexcept
    {
        auto current = next_.load(std::memory_order_relaxed);
        while (current && current < std::numeric_limits<ino_t>::max()) {
            if (next_.compare_exchange_weak(current, current + 1, std::memory_order_relaxed)) {
                output = current;
                return true;
            }
        }
        return false;
    }
};

class pipe_stat_metadata {
    struct stat value_;
public:
    pipe_stat_metadata(ino_t inode, uid_t uid, gid_t gid, const struct timespec& created) noexcept
    {
        // Anonymous pipes have no backing mount or device node. NODEV is a
        // separate namespace from the mounted filesystems in this profile.
        std::memset(&value_, 0, sizeof(value_));
        value_.st_dev = static_cast<dev_t>(-1);
        value_.st_ino = inode;
        value_.st_mode = S_IFIFO | S_IRUSR | S_IWUSR;
        value_.st_nlink = 1;
        value_.st_uid = uid;
        value_.st_gid = gid;
        value_.st_blksize = 4096;
        value_.st_atim.tv_sec = value_.st_mtim.tv_sec = value_.st_ctim.tv_sec = created.tv_sec;
        value_.st_atim.tv_nsec = value_.st_mtim.tv_nsec = value_.st_ctim.tv_nsec = created.tv_nsec;
    }

    void copy_to(struct stat* output) const noexcept
    {
        // The whole structure, including reserved bytes, is initialized.
        std::memcpy(output, &value_, sizeof(value_));
    }
};

} // namespace osv_sandbox
#endif
