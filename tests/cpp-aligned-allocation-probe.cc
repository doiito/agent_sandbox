// Defensive probe: never dereference the returned allocation or write out of bounds.
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <dlfcn.h>
#include <limits>
#include <malloc.h>
#include <new>
#include <sys/resource.h>

int main()
{
    static_assert(sizeof(std::size_t) == 8, "probe requires a 64-bit target");
    const rlimit address_space{256 * 1024 * 1024, 256 * 1024 * 1024};
    const rlimit cpu{2, 2};
    const rlimit core{0, 0};
    if (setrlimit(RLIMIT_AS, &address_space) || setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_CORE, &core))
        return 2;
    std::set_new_handler(nullptr);
    void* handle = dlopen("libstdc++.so.6", RTLD_NOW | RTLD_NOLOAD);
    void* symbol = handle ? dlsym(handle, "_ZnwmSt11align_val_t") : nullptr;
    Dl_info info{};
    if (!symbol || !dladdr(symbol, &info) || !info.dli_fname)
        return 2;
    std::printf("LIBRARY_PATH %s\n", info.dli_fname);
    using allocate_fn = void* (*)(std::size_t, std::align_val_t);
    auto allocate = reinterpret_cast<allocate_fn>(symbol);
    const std::size_t maximum = std::numeric_limits<std::size_t>::max();
    const std::size_t sizes[] = {0, 17, maximum, maximum - 31, maximum - 4095};
    const std::size_t alignments[] = {64, 4096};
    bool valid = true;
    unsigned accepted_huge = 0;
    for (auto alignment : alignments) {
        for (auto size : sizes) {
            bool huge = size > 1024 * 1024 * 1024;
            try {
                void* pointer = allocate(size, static_cast<std::align_val_t>(alignment));
                if (!pointer)
                    return 2;
                auto usable = malloc_usable_size(pointer);
                bool aligned = reinterpret_cast<std::uintptr_t>(pointer) % alignment == 0;
                if (huge)
                    ++accepted_huge;
                else
                    valid = valid && aligned && usable >= size;
                std::printf("CASE {\"size\":%zu,\"alignment\":%zu,\"rejected\":false,\"usable\":%zu,\"aligned\":%s}\n",
                    size, alignment, usable, aligned ? "true" : "false");
                ::operator delete(pointer, static_cast<std::align_val_t>(alignment));
            } catch (const std::bad_alloc&) {
                std::printf("CASE {\"size\":%zu,\"alignment\":%zu,\"rejected\":true}\n", size, alignment);
                if (!huge)
                    valid = false;
            } catch (...) {
                return 2;
            }
        }
    }
    std::printf("ALIGNED_ALLOCATION_RESULT {\"valid_controls\":%s,\"accepted_huge\":%u,\"safe\":%s}\n",
        valid ? "true" : "false", accepted_huge, valid && !accepted_huge ? "true" : "false");
    dlclose(handle);
    return valid ? (accepted_huge ? 1 : 0) : 2;
}
