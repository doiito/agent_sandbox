/* SPDX-License-Identifier: BSD-3-Clause */
/* Execute the actual shared entrypoint in a fresh Linux process for build tests. */
#include <dlfcn.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    if (argc < 3)
        return 125;
    void *handle = dlopen(argv[1], RTLD_NOW | RTLD_GLOBAL);
    if (!handle) {
        fprintf(stderr, "%s\n", dlerror());
        return 125;
    }
    int (*entry)(int, char **) = dlsym(handle, "main");
    if (!entry) {
        fprintf(stderr, "%s\n", dlerror());
        return 125;
    }
    return entry(argc - 1, argv + 1);
}
