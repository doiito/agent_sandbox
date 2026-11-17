#!/usr/bin/env python3
"""Apply the pinned OSv vsock overlay without overwriting unrelated changes."""
import argparse
import hashlib
import json
import pathlib
import subprocess

PIN = "0e34e4dc2b278b7f64e4169abbf297b7de46fb6b"
ROOT = pathlib.Path(__file__).resolve().parents[1]

REPLACEMENTS = {
    "fs/vfs/vfs_syscalls.cc": [(
        'sys_link(char *oldpath, char *newpath)\n{\n\tstruct dentry *olddp, *newdp, *newdirdp;\n',
        'sys_link(char *oldpath, char *newpath)\n{\n\tstruct dentry *olddp, *newdp = nullptr, *newdirdp;\n',
    ), (
        '\tdrele(olddp);\n\tdrele(newdp);\n\treturn error;\n',
        '\tdrele(olddp);\n\tif (newdp) drele(newdp);\n\treturn error;\n',
    ), (
        '\tvn_lock(dp->d_vnode);\n\terror = VOP_TRUNCATE(dp->d_vnode, length);\n',
        '\tif (dp->d_mount->m_flags & MNT_RDONLY) {\n'
        '\t\tdrele(dp);\n\t\treturn EROFS;\n\t}\n'
        '\tvn_lock(dp->d_vnode);\n\terror = VOP_TRUNCATE(dp->d_vnode, length);\n',
    ), (
        '\tvp = fp->f_dentry->d_vnode;\n\tvn_lock(vp);\n\terror = VOP_TRUNCATE(vp, length);\n',
        '\tif (fp->f_dentry->d_mount->m_flags & MNT_RDONLY) return EROFS;\n'
        '\tvp = fp->f_dentry->d_vnode;\n\tvn_lock(vp);\n\terror = VOP_TRUNCATE(vp, length);\n',
    )],
    "fs/ramfs/ramfs_vnops.cc": [(
        '#include "ramfs.h"\n',
        '#include "ramfs.h"\n#include <new>\n',
    ), (
        '    np->rn_file_segments_by_offset = new std::map<off_t,struct ramfs_file_segment>();\n',
        '    np->rn_file_segments_by_offset = new (std::nothrow) std::map<off_t,struct ramfs_file_segment>();\n'
        '    if (!np->rn_file_segments_by_offset) {\n'
        '        free(np->rn_name);\n        free(np);\n        return nullptr;\n    }\n',
    ), (
        'static int\nramfs_remove_node(',
        '#include "readonly-inputs-impl.hh"\n\nstatic int\nramfs_remove_node(',
    )],
    "fs/ramfs/ramfs_vfsops.cc": [(
        '#include "ramfs.h"\n',
        '#include "ramfs.h"\n#include "readonly-inputs.hh"\n',
    ), (
        '    mp->m_root->d_vnode->v_data = np;\n    return 0;\n',
        '    mp->m_root->d_vnode->v_data = np;\n'
        '    if (dev && !strcmp(dev, OSV_INPUT_RAMFS_DEVICE)) {\n'
        '        return ramfs_import_readonly_inputs(mp->m_root->d_vnode,\n'
        '            (flags & MNT_RDONLY) ? static_cast<const ramfs_input_mount_data *>(data) : nullptr);\n'
        '    }\n    return 0;\n',
    )],
    "libc/time.cc": [(
        '#include "pthread.hh"\n',
        '#include "pthread.hh"\n#include "clock-sleep.hh"\n',
    ), (
        '''    //We ignore the "remain" argument same way we do it above in nanosleep()
    //This argument is only relevant if the "sleeping" thread is interrupted
    //by signals. But OSv signal implementation is limited and would not allow
    //for such a scenario and both nanosleep() and clock_nanosleep() would
    //never return EINTR
    if (flags || clock_id != CLOCK_REALTIME) {
        return ENOTSUP;
    }
    sched::thread::sleep(std::chrono::nanoseconds(convert(*request)));
    return 0;''',
        '''    // Current OSv scheduler waits are not interrupted by signals, so
    // remain is unchanged. Return the POSIX error number, without changing errno.
    return osv_sandbox::clock_sleep(clock_id, flags, request,
        [](clockid_t id) -> int64_t {
            return id == CLOCK_MONOTONIC
                ? osv::clock::uptime::now().time_since_epoch().count()
                : osv::clock::wall::now().time_since_epoch().count();
        },
        [](std::chrono::nanoseconds delay) { sched::thread::sleep(delay); });''',
    )],
    "fs/rofs/rofs_vnops.cc": [(
        '#include "rofs.hh"\n',
        '#include "rofs.hh"\n#include "bounded-read.hh"\n#include <osv/mempool.hh>\n',
    ), (
        '''    int rv = 0;
    int error = -1;
    uint64_t block = inode->data_offset;
    uint64_t offset = 0;

    // Total read amount is what they requested, or what is left
    uint64_t read_amt = std::min<uint64_t>(inode->file_size - uio->uio_offset, uio->uio_resid);

    // Calculate which block we need actually need to read
    block += uio->uio_offset / sb->block_size;
    offset = uio->uio_offset % sb->block_size;

    uint64_t block_count = (offset + read_amt) / sb->block_size;
    if ((offset + read_amt) % sb->block_size > 0)
        block_count++;

    void *buf = malloc(BSIZE * block_count);

    print("[rofs] rofs_read [%d], inode: %d, [%d -> %d] at %d of %d bytes\\n",
          sched::thread::current()->id(), inode->inode_no, block, block_count, uio->uio_offset, read_amt);

    error = rofs_read_blocks(device, block, block_count, buf);

    if (error) {
        kprintf("[rofs_read] Error reading data\\n");
        free(buf);
        return error;
    }

    rv = uiomove(buf + offset, read_amt, uio);

    free(buf);
    return rv;''',
        '''    if (sb->block_size != osv_sandbox::rofs_sector_bytes) {
        return EIO;
    }
    return osv_sandbox::bounded_rofs_read(inode->data_offset, inode->file_size,
        uio->uio_offset, uio->uio_resid,
        [](size_t size) {
            return memory::alloc_phys_contiguous_aligned(size, mmu::page_size, false);
        },
        [](void* buffer) { memory::free_phys_contiguous_aligned(buffer); },
        [device](uint64_t block, uint64_t sectors, void* buffer) {
            return rofs_read_blocks(device, block, sectors, buffer);
        },
        [uio](void* buffer, size_t size) { return uiomove(buffer, size, uio); });''',
    )],
    "drivers/virtio-blk.cc": [(
        '        req->res.status = 0;\n',
        '        // An unparsed or incomplete request must not retain success.\n'
        '        req->res.status = VIRTIO_BLK_S_IOERR;\n',
    )],
    "runtime.cc": [(
        '#include <osv/drivers_config.h>\n',
        '#include <osv/drivers_config.h>\n'
        '#if CONF_drivers_virtio_vsock\n'
        'extern "C" void osv_sandbox_notify_exit(int status);\n'
        '#endif\n',
    ), (
        'void exit(int status)\n{\n    debugf(',
        'void exit(int status)\n{\n'
        '#if CONF_drivers_virtio_vsock\n'
        '    osv_sandbox_notify_exit(status);\n'
        '#endif\n    debugf(',
    )],
    "libc/pipe.cc": [(
        '#include "pipe_buffer.hh"\n',
        '#include "pipe_buffer.hh"\n#include "pipe-stat.hh"\n#include <memory>\n#include <new>\n',
    ), (
        '    explicit pipe_file(std::unique_ptr<pipe_reader>&& s);\n'
        '    explicit pipe_file(std::unique_ptr<pipe_writer>&& s);\n',
        '    pipe_file(std::unique_ptr<pipe_reader>&& s, std::shared_ptr<const osv_sandbox::pipe_stat_metadata> metadata);\n'
        '    pipe_file(std::unique_ptr<pipe_writer>&& s, std::shared_ptr<const osv_sandbox::pipe_stat_metadata> metadata);\n'
        '    virtual int stat(struct stat* value) override;\n',
    ), (
        'private:\n    pipe_writer* writer = nullptr;\n',
        'private:\n    std::shared_ptr<const osv_sandbox::pipe_stat_metadata> metadata_;\n'
        '    pipe_writer* writer = nullptr;\n',
    ), (
        'pipe_file::pipe_file(std::unique_ptr<pipe_writer>&& s)\n'
        '    : special_file(FWRITE, DTYPE_UNSPEC)\n',
        'pipe_file::pipe_file(std::unique_ptr<pipe_writer>&& s, std::shared_ptr<const osv_sandbox::pipe_stat_metadata> metadata)\n'
        '    : special_file(FWRITE, DTYPE_UNSPEC)\n    , metadata_(std::move(metadata))\n',
    ), (
        'pipe_file::pipe_file(std::unique_ptr<pipe_reader>&& s)\n'
        '    : special_file(FREAD, DTYPE_UNSPEC)\n',
        'pipe_file::pipe_file(std::unique_ptr<pipe_reader>&& s, std::shared_ptr<const osv_sandbox::pipe_stat_metadata> metadata)\n'
        '    : special_file(FREAD, DTYPE_UNSPEC)\n    , metadata_(std::move(metadata))\n',
    ), (
        'int pipe_file::close()\n',
        'int pipe_file::stat(struct stat* value)\n{\n    metadata_->copy_to(value);\n    return 0;\n}\n\n'
        'int pipe_file::close()\n',
    ), (
        '    auto b = new pipe_buffer;\n'
        '    std::unique_ptr<pipe_reader> s1{new pipe_reader(b)};\n'
        '    std::unique_ptr<pipe_writer> s2{new pipe_writer(b)};\n'
        '    try {\n'
        '        fileref f1 = make_file<pipe_file>(move(s1));\n'
        '        fileref f2 = make_file<pipe_file>(move(s2));\n',
        '    try {\n'
        '        struct timespec created;\n'
        '        if (clock_gettime(CLOCK_REALTIME, &created)) return libc_error(errno);\n'
        '        static osv_sandbox::pipe_inode_allocator identifiers;\n'
        '        ino_t inode;\n'
        '        if (!identifiers.allocate(inode)) return libc_error(EOVERFLOW);\n'
        '        auto metadata = std::make_shared<const osv_sandbox::pipe_stat_metadata>(inode, geteuid(), getegid(), created);\n'
        '        pipe_buffer_ref buffer(new pipe_buffer);\n'
        '        std::unique_ptr<pipe_reader> s1{new pipe_reader(buffer.get())};\n'
        '        std::unique_ptr<pipe_writer> s2{new pipe_writer(buffer.get())};\n'
        '        fileref f1 = make_file<pipe_file>(move(s1), metadata);\n'
        '        fileref f2 = make_file<pipe_file>(move(s2), metadata);\n',
    ), (
        '    } catch (int error) {\n        return libc_error(error);\n    }\n',
        '    } catch (int error) {\n        return libc_error(error);\n'
        '    } catch (const std::bad_alloc&) {\n        return libc_error(ENOMEM);\n'
        '    } catch (...) {\n        return libc_error(EIO);\n    }\n',
    )],
    "fs/vfs/main.cc": [(
        '        trace_vfs_isatty_err(errno);\n        return -1;\n',
        '        trace_vfs_isatty_err(errno);\n        return 0;\n',
    ), (
        '    trace_vfs_isatty_ret(istty);\n',
        '    if (!istty) errno = ENOTTY;\n    trace_vfs_isatty_ret(istty);\n',
    ), (
        'OSV_LIBC_API\nint fchown(int fd, uid_t owner, gid_t group)\n',
        '#include "readonly-ownership.hh"\n\nOSV_LIBC_API\nint fchown(int fd, uid_t owner, gid_t group)\n',
    ), (
        '    trace_vfs_fchown(fd, owner, group);\n    WARN_STUBBED();\n',
        '    trace_vfs_fchown(fd, owner, group);\n'
        '    int error = readonly_ownership_fd(fd);\n'
        '    if (error) { errno = error; return -1; }\n    WARN_STUBBED();\n',
    ), (
        'int chown(const char *path, uid_t owner, gid_t group)\n{\n    WARN_STUBBED();\n',
        'int chown(const char *path, uid_t owner, gid_t group)\n{\n'
        '    int error = readonly_ownership_path(path, false);\n'
        '    if (error) { errno = error; return -1; }\n    WARN_STUBBED();\n',
    ), (
        'int lchown(const char *path, uid_t owner, gid_t group)\n{\n    WARN_STUBBED();\n',
        'int lchown(const char *path, uid_t owner, gid_t group)\n{\n'
        '    int error = readonly_ownership_path(path, true);\n'
        '    if (error) { errno = error; return -1; }\n    WARN_STUBBED();\n',
    )],
    "conf/profiles/x64/base.mk": [(
        "export conf_drivers_virtio_rng?=0\n",
        "export conf_drivers_virtio_vsock?=0\n"
        "ifeq ($(conf_drivers_virtio_vsock),1)\n"
        "export conf_drivers_virtio?=1\n"
        "endif\n\n"
        "export conf_drivers_virtio_rng?=0\n",
    )],
    "drivers/virtio-mmio.hh": [(
        "    virtual u8 read_config(u32 offset);\n",
        "    virtual u8 read_config(u32 offset);\n"
        "    u64 read_config64(u32 offset);\n",
    )],
    "drivers/virtio-mmio.cc": [(
        "u8 mmio_device::read_config(u32 offset)\n"
        "{\n    return mmio_getb(_addr_mmio + VIRTIO_MMIO_CONFIG + offset);\n}\n",
        "u8 mmio_device::read_config(u32 offset)\n"
        "{\n    return mmio_getb(_addr_mmio + VIRTIO_MMIO_CONFIG + offset);\n}\n\n"
        "u64 mmio_device::read_config64(u32 offset)\n"
        "{\n    return mmio_getq(_addr_mmio + VIRTIO_MMIO_CONFIG + offset);\n}\n",
    )],
    "Makefile": [(
        "drivers += drivers/virtio-scsi.o\n"
        "drivers += drivers/virtio-rng.o\n"
        "drivers += drivers/virtio-balloon.o\n",
        "drivers += drivers/virtio-scsi.o\n"
        "drivers += drivers/virtio-rng.o\n"
        "ifeq ($(conf_drivers_virtio_vsock),1)\n"
        "drivers += drivers/virtio-vsock.o\n"
        "endif\n"
        "drivers += drivers/virtio-balloon.o\n",
    ), (
        "drivers += drivers/virtio-scsi.o\n"
        "drivers += drivers/virtio-rng.o\n"
        "ifeq ($(conf_drivers_virtio_vsock),1)\n"
        "drivers += drivers/virtio-vsock.o\n"
        "endif\n"
        "drivers += drivers/virtio-balloon.o\n"
        "drivers += drivers/virtio-fs.o\nendif\n",
        "ifeq ($(conf_drivers_virtio_scsi),1)\n"
        "drivers += drivers/virtio-scsi.o\nendif\n"
        "ifeq ($(conf_drivers_virtio_rng),1)\n"
        "drivers += drivers/virtio-rng.o\nendif\n"
        "ifeq ($(conf_drivers_virtio_vsock),1)\n"
        "drivers += drivers/virtio-vsock.o\nendif\n"
        "ifeq ($(conf_drivers_pci),1)\n"
        "drivers += drivers/virtio-balloon.o\nendif\n"
        "ifeq ($(conf_drivers_virtio_fs),1)\n"
        "drivers += drivers/virtio-fs.o\nendif\n"
        "endif\n",
    ), (
        "objects += core/io_uring.o\n",
        "ifeq ($(conf_networking_stack),1)\n"
        "objects += core/io_uring.o\n"
        "else\n"
        "objects += core/io_uring-disabled.o\n"
        "endif\n",
    ), (
        "ifeq ($(conf_networking_stack),1)\n"
        "objects += core/io_uring.o\nendif\n",
        "ifeq ($(conf_networking_stack),1)\n"
        "objects += core/io_uring.o\n"
        "else\n"
        "objects += core/io_uring-disabled.o\n"
        "endif\n",
    ), (
        "objects += core/run.o\n",
        "objects += core/run.o\n"
        "ifeq ($(conf_drivers_virtio_vsock),1)\n"
        "objects += core/sandbox-run.o\n"
        "endif\n",
    ), (
        "$(out)/loader.elf: $(stage1_targets) arch/$(arch)/loader.ld $(out)/bootfs.o $(out)/libvdso-content.o $(loader_options_dep) $(version_script_file)\n",
        "$(out)/loader.elf: $(stage1_targets) arch/$(arch)/loader.ld $(out)/bootfs.o $(out)/libvdso-content.o $(loader_options_dep) $(version_script_file) conf/profiles/$(arch)/$(conf_drivers_profile).mk\n",
    ), (
        "$(filter-out $(loader_options_dep),$^))) \\\n"
        "\t    $(linker_archives_options) $(conf_linker_extra_options), \\\n"
        "\t\tLINK loader.elf)",
        "$(filter-out $(loader_options_dep) conf/profiles/$(arch)/$(conf_drivers_profile).mk,$^))) \\\n"
        "\t    $(linker_archives_options) $(conf_linker_extra_options), \\\n"
        "\t\tLINK loader.elf)",
    )],
    "arch/x64/arch-setup.cc": [(
        "#if CONF_drivers_virtio_rng\n#include \"drivers/virtio-rng.hh\"\n#endif\n",
        "#if CONF_drivers_virtio_rng\n#include \"drivers/virtio-rng.hh\"\n#endif\n"
        "#if CONF_drivers_virtio_vsock\n#include \"drivers/virtio-vsock.hh\"\n#endif\n",
    ), (
        "    drvman->register_driver(virtio::rng::probe);\n#endif\n",
        "    drvman->register_driver(virtio::rng::probe);\n#endif\n"
        "#if CONF_drivers_virtio_vsock\n"
        "    drvman->register_driver(virtio::vsock::probe);\n#endif\n",
    ), (
        "#if CONF_drivers_virtio\n"
        "    drvman->register_driver(virtio::balloon::probe);\n#endif\n",
        "#if CONF_drivers_pci\n"
        "    drvman->register_driver(virtio::balloon::probe);\n#endif\n",
    )],
    "conf/profiles/x64/kconfig": [(
        "config drivers_profile_microvm\n  bool \"MicroVM Device Drivers\"\n",
        "config drivers_profile_microvm\n  bool \"MicroVM Device Drivers\"\n"
        "config drivers_profile_agent-sandbox\n  bool \"OSv Agent Sandbox (MMIO only)\"\n",
    )],
}

COPIES = {
    "osv-native/fs/vfs/readonly-ownership.hh": "fs/vfs/readonly-ownership.hh",
    "osv-native/include/osv/input-files.h": "include/osv/input-files.h",
    "osv-native/include/osv/sandbox-input.h": "include/osv/sandbox-input.h",
    "osv-native/fs/ramfs/readonly-inputs.hh": "fs/ramfs/readonly-inputs.hh",
    "osv-native/fs/ramfs/readonly-inputs-impl.hh": "fs/ramfs/readonly-inputs-impl.hh",
    "osv-native/libc/clock-sleep.hh": "libc/clock-sleep.hh",
    "osv-native/fs/rofs/bounded-read.hh": "fs/rofs/bounded-read.hh",
    "osv-native/core/exit-bridge.hh": "core/exit-bridge.hh",
    "osv-native/apps/job-agent/completion.h": "apps/job-agent/completion.h",
    "osv-native/libc/pipe-stat.hh": "libc/pipe-stat.hh",
    "osv-native/apps/pipe-stat-probe/main.c": "apps/pipe-stat-probe/main.c",
    "osv-native/apps/pipe-stat-probe/Makefile": "apps/pipe-stat-probe/Makefile",
    "osv-native/apps/pipe-stat-probe/module.py": "apps/pipe-stat-probe/module.py",
    "osv-native/apps/pipe-stat-probe/usr.manifest": "apps/pipe-stat-probe/usr.manifest",
    "osv-native/drivers/virtio-vsock.cc": "drivers/virtio-vsock.cc",
    "osv-native/drivers/virtio-vsock.hh": "drivers/virtio-vsock.hh",
    "osv-native/drivers/vsock-protocol.hh": "drivers/vsock-protocol.hh",
    "osv-native/core/io_uring-disabled.cc": "core/io_uring-disabled.cc",
    "osv-native/core/sandbox-run.cc": "core/sandbox-run.cc",
    "osv-native/include/osv/vsock.h": "include/osv/vsock.h",
    "osv-native/include/osv/sandbox-run.h": "include/osv/sandbox-run.h",
    "osv-native/conf/profiles/x64/agent-sandbox.mk": "conf/profiles/x64/agent-sandbox.mk",
    "osv-native/exported_symbols/osv_vsock.symbols": "exported_symbols/osv_vsock.symbols",
    "osv-native/apps/vsock-test/Makefile": "apps/vsock-test/Makefile",
    "osv-native/apps/vsock-test/module.py": "apps/vsock-test/module.py",
    "osv-native/apps/vsock-test/usr.manifest": "apps/vsock-test/usr.manifest",
    "osv-native/apps/vsock-test/main.c": "apps/vsock-test/main.c",
    "osv-native/apps/vsock-test/task-probe.c": "apps/vsock-test/task-probe.c",
    "osv-native/apps/job-agent/Makefile": "apps/job-agent/Makefile",
    "osv-native/apps/job-agent/module.py": "apps/job-agent/module.py",
    "osv-native/apps/job-agent/usr.manifest": "apps/job-agent/usr.manifest",
    "osv-native/apps/job-agent/main.c": "apps/job-agent/main.c",
    "osv-native/apps/job-agent/pristine.h": "apps/job-agent/pristine.h",
    "osv-native/apps/job-agent/pristine-inputs.h": "apps/job-agent/pristine-inputs.h",
    "osv-native/apps/input-mount-test/Makefile": "apps/input-mount-test/Makefile",
    "osv-native/apps/input-mount-test/module.py": "apps/input-mount-test/module.py",
    "osv-native/apps/input-mount-test/usr.manifest": "apps/input-mount-test/usr.manifest",
    "osv-native/apps/input-mount-test/main.c": "apps/input-mount-test/main.c",
    "osv-native/apps/python-science/Makefile": "apps/python-science/Makefile",
    "osv-native/apps/python-science/module.py": "apps/python-science/module.py",
    "osv-native/apps/python-science/usr.manifest": "apps/python-science/usr.manifest",
}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--osv-dir", type=pathlib.Path, default=ROOT / "osv-upstream")
    args = parser.parse_args()
    target = args.osv_dir.resolve()
    head = subprocess.check_output(["git", "-C", str(target), "rev-parse", "HEAD"], text=True).strip()
    if head != PIN:
        raise SystemExit(f"OSv HEAD {head} differs from pinned {PIN}")
    state_path = target / ".osv-sandbox-overlay.json"
    state = json.loads(state_path.read_text()) if state_path.exists() else {}

    # Check every input first, so a conflict cannot leave a partial overlay.
    writes = {}
    for name, substitutions in REPLACEMENTS.items():
        path = target / name
        content = path.read_text()
        for index, (before, after) in enumerate(substitutions):
            if name == "Makefile" and index == 0 and (
                "ifeq ($(conf_drivers_virtio_scsi),1)\n"
                "drivers += drivers/virtio-scsi.o\nendif\n"
            ) in content:
                continue
            if name == "Makefile" and index == 2 and (
                "ifeq ($(conf_networking_stack),1)\n"
                "objects += core/io_uring.o\n"
            ) in content:
                continue
            if after in content:
                continue
            if content.count(before) != 1:
                raise SystemExit(f"unexpected upstream context: {name}")
            content = content.replace(before, after, 1)
        writes[path] = content.encode()
    for source, destination in COPIES.items():
        data = (ROOT / source).read_bytes()
        path = target / destination
        if path.exists() and path.read_bytes() != data:
            current_hash = hashlib.sha256(path.read_bytes()).hexdigest()
            if state.get(destination) != current_hash:
                raise SystemExit(f"overlay conflict: {destination}")
        writes[path] = data
    for path, data in writes.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists() or path.read_bytes() != data:
            path.write_bytes(data)
    state_path.write_text(json.dumps({destination: hashlib.sha256((ROOT / source).read_bytes()).hexdigest()
                                      for source, destination in COPIES.items()}, indent=2) + "\n")
    print(f"OSv native overlay applied to {target}")


if __name__ == "__main__":
    main()
