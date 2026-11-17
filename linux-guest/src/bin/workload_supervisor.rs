//! Short-lived private supervisor; the long-lived agent keeps mimalloc.
//! The shared dispatcher enforces its parent, credentials, FDs and protocol.
use firecracker_linux_agent::workload;

#[global_allocator]
static ALLOCATOR: std::alloc::System = std::alloc::System;

fn main() {
    std::process::exit(workload::dispatch_helper().unwrap_or(2));
}
