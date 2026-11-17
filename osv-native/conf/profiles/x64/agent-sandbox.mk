conf_drivers_mmio?=1
conf_drivers_virtio_vsock?=1
conf_drivers_virtio_blk?=1
conf_drivers_virtio_net?=0
conf_drivers_pci?=0
conf_drivers_acpi?=0

# --gc-sections otherwise drops the C ABI even when version_script lists it.
conf_linker_extra_options += --undefined=osv_vsock_listen \
    --undefined=osv_vsock_accept --undefined=osv_vsock_connect \
    --undefined=osv_vsock_recv --undefined=osv_vsock_send \
    --undefined=osv_vsock_shutdown --undefined=osv_vsock_close \
    --undefined=osv_vsock_cid --undefined=osv_sandbox_run_module \
    --undefined=osv_sandbox_register_exit_callback \
    --undefined=osv_sandbox_mount_inputs_v1
