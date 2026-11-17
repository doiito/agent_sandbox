/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef OSV_SANDBOX_EXIT_BRIDGE_HH
#define OSV_SANDBOX_EXIT_BRIDGE_HH

#include <atomic>
#include <cerrno>
#include <osv/sandbox-run.h>

namespace osv_sandbox {

class exit_bridge_binding {
    std::atomic<unsigned> published_;
    osv_sandbox_exit_callback callback_;
    void* context_;
public:
    constexpr exit_bridge_binding() noexcept : published_(0), callback_(nullptr), context_(nullptr) {}

    int register_callback(uint32_t version, osv_sandbox_exit_callback callback, void* context) noexcept
    {
        if (version != OSV_SANDBOX_EXIT_ABI) return -EPROTONOSUPPORT;
        if (!callback || !context) return -EINVAL;
        unsigned expected = 0;
        if (!published_.compare_exchange_strong(expected, 1, std::memory_order_acq_rel))
            return -EALREADY;
        callback_ = callback;
        context_ = context;
        published_.store(2, std::memory_order_release);
        return 0;
    }

    bool notify(int status)
    {
        if (published_.load(std::memory_order_acquire) != 2) return false;
        callback_(context_, status);
        return true;
    }
};

} // namespace osv_sandbox
#endif
