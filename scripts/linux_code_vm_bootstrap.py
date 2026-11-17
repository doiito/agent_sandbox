"""Stage matching modules for the optional Debian ARM verification kernel."""
import hashlib
import json
from pathlib import Path
import shutil


def digest(path):
    with Path(path).open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def stage_arm_modules(rootfs, directory):
    rootfs, directory = Path(rootfs), Path(directory).resolve()
    metadata = directory / 'order.json'
    closure = json.loads(metadata.read_text())
    order = closure['order']
    if (closure.get('protocol') != 'osv-validation-kernel-module-closure/v1'
            or not order or len(order) > 32 or len(set(order)) != len(order)
            or set(order) != set(closure['modules'])
            or any(not name.isascii() or not name.isidentifier() or len(name) > 64 for name in order)):
        raise ValueError('invalid ARM verification module closure')
    loaded = set()
    for name in order:
        record = closure['modules'][name]
        source = directory / (name + '.ko')
        if source.is_symlink() or digest(source) != record['sha256']:
            raise ValueError('ARM verification module differs from its seal: ' + name)
        if any(dependency.replace('-', '_') not in loaded for dependency in record['depends'].split(',') if dependency):
            raise ValueError('ARM verification modules are not in dependency order')
        loaded.add(name)
    elf = rootfs / 'validation/service-init'
    if elf.exists():
        raise ValueError('verification init has already been wrapped')
    (rootfs / 'init').replace(elf)
    modules = rootfs / 'validation/modules'
    modules.mkdir()
    for name in order:
        shutil.copyfile(directory / (name + '.ko'), modules / (name + '.ko'))
    wrapper = '''#!/bin/sh
set -eu
/bin/busybox mkdir -p /proc /sys /dev
/bin/busybox mount -t proc proc /proc || test -d /proc/self
/bin/busybox mount -t sysfs sysfs /sys || test -d /sys/kernel
/bin/busybox mount -t devtmpfs devtmpfs /dev || test -c /dev/null
for name in MODULE_ORDER; do
    /bin/busybox insmod /validation/modules/$name.ko || test -d /sys/module/$name
done
exec /validation/service-init "$@"
'''.replace('MODULE_ORDER', ' '.join(order))
    (rootfs / 'init').write_text(wrapper)
    (rootfs / 'init').chmod(0o755)
    return {'module_closure': closure, 'metadata_sha256': digest(metadata),
            'rust_test_elf_sha256': digest(elf), 'wrapper_sha256': digest(rootfs / 'init'),
            'verification_only': True}
