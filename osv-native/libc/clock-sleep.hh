/* SPDX-License-Identifier: BSD-3-Clause */
#ifndef OSV_SANDBOX_CLOCK_SLEEP_HH
#define OSV_SANDBOX_CLOCK_SLEEP_HH

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <time.h>

namespace osv_sandbox {

// clock_nanosleep returns an error number directly. It never owns errno or
// remain; the current OSv scheduler cannot interrupt these waits with signals.
template <typename ClockNow, typename Sleep>
int clock_sleep(clockid_t clock_id, int flags, const timespec* request,
                ClockNow now, Sleep sleep)
{
    if (!request) return EFAULT;
    if ((flags != 0 && flags != TIMER_ABSTIME) || request->tv_sec < 0 ||
            request->tv_nsec < 0 || request->tv_nsec >= 1000000000) return EINVAL;
    if (clock_id != CLOCK_REALTIME && clock_id != CLOCK_MONOTONIC) return ENOTSUP;

    const __int128 requested = static_cast<__int128>(request->tv_sec) * 1000000000 + request->tv_nsec;
    const bool absolute = flags == TIMER_ABSTIME;
    __int128 remaining = absolute ? requested - now(clock_id) : requested;
    while (remaining > 0) {
        // Avoid overflowing the scheduler's signed nanosecond deadline for
        // huge requests. Absolute waits also observe wall-clock adjustments.
        const int64_t part = remaining > 1000000000 ? 1000000000 : static_cast<int64_t>(remaining);
        sleep(std::chrono::nanoseconds(part));
        remaining = absolute ? requested - now(clock_id) : remaining - part;
    }
    return 0;
}

}
#endif
