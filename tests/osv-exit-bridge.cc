/* SPDX-License-Identifier: BSD-3-Clause */
#include "../osv-native/core/exit-bridge.hh"
#include <array>
#include <cassert>
#include <iostream>
#include <thread>
#include <vector>

struct context {
    unsigned tag = 0;
    std::atomic<unsigned> calls{0};
    std::atomic<long> sum{0};
};

static void callback(void* opaque, int status)
{
    auto value = static_cast<context*>(opaque);
    assert(value->tag >= 1 && value->tag <= 16);
    value->sum.fetch_add(status, std::memory_order_relaxed);
    value->calls.fetch_add(1, std::memory_order_relaxed);
}

int main()
{
    osv_sandbox::exit_bridge_binding bridge;
    std::array<context, 16> contexts;
    for (unsigned i = 0; i < contexts.size(); ++i) contexts[i].tag = i + 1;
    assert(!bridge.notify(7));
    assert(bridge.register_callback(0, callback, &contexts[0]) == -EPROTONOSUPPORT);
    assert(bridge.register_callback(1, nullptr, &contexts[0]) == -EINVAL);
    assert(bridge.register_callback(1, callback, nullptr) == -EINVAL);
    assert(!bridge.notify(7));
    std::atomic<context*> chosen{nullptr};
    std::atomic<unsigned> registration_winners{0}, accepted_notifications{0};
    std::atomic<bool> stop{false};
    std::thread observer([&] {
        while (!stop.load(std::memory_order_acquire)) {
            if (bridge.notify(-7)) accepted_notifications.fetch_add(1, std::memory_order_relaxed);
            else std::this_thread::yield();
        }
    });
    std::vector<std::thread> registrars;
    for (auto& value : contexts) {
        registrars.emplace_back([&bridge, &value, &chosen, &registration_winners] {
            int status = bridge.register_callback(1, callback, &value);
            assert(status == 0 || status == -EALREADY);
            if (!status) {
                registration_winners.fetch_add(1, std::memory_order_relaxed);
                chosen.store(&value, std::memory_order_release);
            }
        });
    }
    for (auto& thread : registrars) thread.join();
    stop.store(true, std::memory_order_release);
    observer.join();
    auto winner = chosen.load(std::memory_order_acquire);
    assert(winner && registration_winners == 1);
    assert(bridge.register_callback(1, callback, winner) == -EALREADY);
    assert(winner->calls == accepted_notifications.load());
    assert(winner->sum == -7L * accepted_notifications.load());
    std::vector<std::thread> notifiers;
    for (unsigned i = 0; i < 8; ++i) {
        notifiers.emplace_back([&] {
            for (unsigned n = 0; n < 4096; ++n) assert(bridge.notify(19));
        });
    }
    for (auto& thread : notifiers) thread.join();
    assert(winner->calls == accepted_notifications.load() + 32768);
    assert(winner->sum == -7L * accepted_notifications.load() + 19L * 32768);
    for (auto& value : contexts) if (&value != winner) assert(value.calls == 0);
    std::cout << "EXIT_BRIDGE_BINDING_TEST_PASS registrars=16 notifications=32768 raw_status=preserved\n";
}
