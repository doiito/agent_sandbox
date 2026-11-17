/* SPDX-License-Identifier: BSD-3-Clause */
#include "../osv-native/libc/clock-sleep.hh"
#include <cassert>
#include <iostream>
#include <limits>
#include <thread>
#include <vector>

int main()
{
    using osv_sandbox::clock_sleep;
    using ns = std::chrono::nanoseconds;
    int reads = 0;
    int64_t current = 100000000000;
    std::vector<int64_t> waits;
    auto now = [&](clockid_t) { ++reads; return current; };
    auto sleep = [&](ns interval) { assert(interval.count() > 0 && interval.count() <= 1000000000); waits.push_back(interval.count()); current += interval.count(); };
    for (clockid_t clock : {CLOCK_REALTIME, CLOCK_MONOTONIC}) {
        waits.clear(); reads = 0;
        timespec relative{0, 125000000};
        errno = E2BIG;
        assert(clock_sleep(clock, 0, &relative, now, sleep) == 0);
        assert(waits == std::vector<int64_t>{125000000} && reads == 0 && errno == E2BIG);
        timespec absolute{current / 1000000000, (current % 1000000000) + 5};
        waits.clear();
        assert(clock_sleep(clock, TIMER_ABSTIME, &absolute, now, sleep) == 0);
        assert(waits == std::vector<int64_t>{5});
        waits.clear();
        assert(clock_sleep(clock, TIMER_ABSTIME, &absolute, now, sleep) == 0 && waits.empty());
        timespec zero{};
        assert(clock_sleep(clock, 0, &zero, now, sleep) == 0 && waits.empty());
    }
    const int old_reads = reads;
    for (timespec invalid : {timespec{-1, 0}, timespec{0, -1}, timespec{0, 1000000000}})
        assert(clock_sleep(CLOCK_MONOTONIC, 0, &invalid, now, sleep) == EINVAL);
    timespec valid{0, 1};
    assert(clock_sleep(CLOCK_MONOTONIC, 2, &valid, now, sleep) == EINVAL);
    assert(clock_sleep(CLOCK_MONOTONIC, 0, nullptr, now, sleep) == EFAULT);
    assert(clock_sleep(CLOCK_THREAD_CPUTIME_ID, 0, &valid, now, sleep) == ENOTSUP);
    assert(reads == old_reads && waits.empty());
    // A wall clock that moves backwards must not produce an early success.
    current = 100000000000; waits.clear();
    timespec deadline{102, 0};
    auto adjusted_sleep = [&](ns interval) {
        sleep(interval);
        if (waits.size() == 1) current -= 500000000;
    };
    assert(clock_sleep(CLOCK_REALTIME, TIMER_ABSTIME, &deadline, now, adjusted_sleep) == 0);
    int64_t elapsed = 0; for (auto value : waits) elapsed += value;
    assert(elapsed == 2500000000 && current == 102000000000);
    // Very large time_t values must reach a bounded positive wait, not wrap.
    struct stop_after_first {};
    timespec huge{std::numeric_limits<time_t>::max(), 999999999};
    for (int flags : {0, TIMER_ABSTIME}) {
        bool bounded = false;
        try {
            clock_sleep(CLOCK_MONOTONIC, flags, &huge, now, [&](ns interval) {
                assert(interval.count() == 1000000000); bounded = true; throw stop_after_first{};
            });
        } catch (const stop_after_first&) {}
        assert(bounded);
    }
    // Use real elapsed time as well as the injected-clock boundary cases.
    const auto started = std::chrono::steady_clock::now();
    timespec real_wait{0, 10000000};
    assert(clock_sleep(CLOCK_MONOTONIC, 0, &real_wait, now,
                       [](ns interval) { std::this_thread::sleep_for(interval); }) == 0);
    assert(std::chrono::steady_clock::now() - started >= ns(10000000));
    std::cout << "CLOCK_SLEEP_TEST_PASS relative absolute expired invalid overflow wall-adjustment errno real-wait\n";
}
