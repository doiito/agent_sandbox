/* SPDX-License-Identifier: BSD-3-Clause */
/* This profile has no network stack. Keep the syscall ABI fail-closed. */
#include <osv/io_uring.h>
#include <errno.h>

extern "C" long sys_io_uring_setup(unsigned, struct io_uring_params*) { return -ENOSYS; }
extern "C" int sys_io_uring_enter(int, unsigned, unsigned, unsigned, const void*, size_t) { return -ENOSYS; }
extern "C" int sys_io_uring_register(int, unsigned, void*, unsigned) { return -ENOSYS; }
