/* SPDX-License-Identifier: BSD-3-Clause */
#include <osv/sandbox-run.h>
#include <osv/app.hh>
#include <osv/export.h>
#include <osv/wait_record.hh>

#include <cerrno>
#include <cstring>
#include <new>
#include <string>
#include <vector>
#include "exit-bridge.hh"

namespace {
osv_sandbox::exit_bridge_binding task_exit_binding;
bool valid_module_path(const char* path) noexcept {
    if (!path || path[0] != '/') return false;
    const auto length = strnlen(path, 256);
    if (length < 5 || length >= 256 || std::strcmp(path + length - 3, ".so")) return false;
    size_t segment_start = 1;
    for (size_t index = 1; index <= length; ++index) {
        const char ch = path[index];
        if (ch == '/' || index == length) {
            const auto segment_length = index - segment_start;
            if (!segment_length || (segment_length == 1 && path[segment_start] == '.') ||
                (segment_length == 2 && path[segment_start] == '.' && path[segment_start + 1] == '.'))
                return false;
            segment_start = index + 1;
            continue;
        }
        if (!((ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
              (ch >= '0' && ch <= '9') || ch == '-' || ch == '_' || ch == '.')) return false;
    }
    return true;
}
}

extern "C" OSV_MODULE_API
int osv_sandbox_register_exit_callback(uint32_t version,
                                     osv_sandbox_exit_callback callback, void* context)
{
    return task_exit_binding.register_callback(version, callback, context);
}

// Internal to the kernel: unregistered/failed callbacks retain normal shutdown.
extern "C" void osv_sandbox_notify_exit(int status)
{
    try {
        task_exit_binding.notify(status);
    } catch (...) {
        // No exception may escape the libc exit boundary or resume user code.
    }
}

extern "C" OSV_MODULE_API
int osv_sandbox_run_module(const char* path, const char* const* argv,
                           size_t argc, int* exit_code) {
    if (!valid_module_path(path) || !argv || !exit_code || argc == 0 || argc > 65)
        return -EINVAL;
    size_t total = 0;
    for (size_t index = 0; index < argc; ++index) {
        if (!argv[index]) return -EINVAL;
        const auto length = strnlen(argv[index], 4097);
        if (length > 4096 || total + length > 32768) return -E2BIG;
        total += length;
    }
    if (std::strcmp(argv[0], path)) return -EINVAL;
    try {
        std::vector<std::string> arguments;
        arguments.reserve(argc);
        for (size_t index = 0; index < argc; ++index) arguments.emplace_back(argv[index]);
        waiter main_done(sched::thread::current());
        int code = 0;
        auto app = osv::application::run(path, arguments, false, nullptr, "main", [&] {
            auto current = osv::application::get_current();
            code = current->get_return_code();
            main_done.wake();
        });
        if (!app) return -EIO;
        // Do not join or unload here. A module may leave background threads;
        // the agent sends one result then powers off this single-use VM.
        main_done.wait();
        *exit_code = code;
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    } catch (const osv::launch_error&) {
        return -ENOENT;
    } catch (...) {
        return -EIO;
    }
}
