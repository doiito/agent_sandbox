//! One allocator boundary for the statically linked musl guest programs.
//! C allocations keep their C allocator; Rust allocations use MiMalloc.

#[cfg(all(target_env = "musl", feature = "mimalloc"))]
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AllocatorIdentity {
    pub name: &'static str,
    pub c_version: u32,
    pub secure_level: u8,
}

#[cfg(all(target_env = "musl", feature = "mimalloc"))]
unsafe extern "C" {
    fn mi_version() -> std::ffi::c_int;
}

/// Force the allocator crate into both guest links and verify the pinned C ABI.
/// This does not read tenant environment variables or change libc ownership.
pub fn initialize() -> AllocatorIdentity {
    #[cfg(all(target_env = "musl", feature = "mimalloc"))]
    {
        // SAFETY: mi_version takes no arguments and returns the linked library's
        // compile-time version. The static sys crate supplies this C symbol.
        let version = unsafe { mi_version() };
        if cfg!(feature = "secure") {
            assert_eq!(
                version, 30302,
                "mimalloc hardened guest secure=4 differs from source lock"
            );
        } else {
            assert_eq!(
                version, 30302,
                "mimalloc benchmark allocator differs from source lock"
            );
        }
        AllocatorIdentity {
            name: "mimalloc",
            c_version: version as u32,
            secure_level: if cfg!(feature = "secure") { 4 } else { 0 },
        }
    }
    #[cfg(not(all(target_env = "musl", feature = "mimalloc")))]
    {
        AllocatorIdentity {
            name: "system",
            c_version: 0,
            secure_level: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::alloc::{GlobalAlloc, Layout, System, alloc_zeroed, dealloc, realloc};

    #[cfg(all(target_env = "musl", feature = "mimalloc"))]
    unsafe extern "C" {
        fn mi_is_in_heap_region(pointer: *const std::ffi::c_void) -> bool;
    }

    fn assert_global_owner(pointer: *const u8) {
        #[cfg(all(target_env = "musl", feature = "mimalloc"))]
        // SAFETY: the test supplies a live allocation, and the query does not
        // mutate or free it. mimalloc accepts any pointer for this predicate.
        assert!(unsafe { mi_is_in_heap_region(pointer.cast()) });
        #[cfg(not(all(target_env = "musl", feature = "mimalloc")))]
        let _ = pointer;
    }

    #[test]
    fn global_rust_allocations_use_the_declared_allocator() {
        let identity = initialize();
        let value = Box::new([42_u8; 73]);
        assert_global_owner(value.as_ptr());
        #[cfg(all(target_env = "musl", feature = "mimalloc"))]
        assert_eq!(identity.name, "mimalloc");
        #[cfg(not(all(target_env = "musl", feature = "mimalloc")))]
        assert_eq!(identity.name, "system");
    }

    #[test]
    fn zero_alignment_growth_and_contents_survive() {
        for alignment in [8, 16, 64, 256, 4096, 65536] {
            let old = Layout::from_size_align(8192, alignment).unwrap();
            let new = Layout::from_size_align(32768, alignment).unwrap();
            // SAFETY: all layouts are nonzero and valid. Each allocation is
            // accessed within its extent, reallocated once, and freed once
            // with the matching Rust global allocator and final layout.
            unsafe {
                let pointer = alloc_zeroed(old);
                assert!(!pointer.is_null());
                assert_eq!(pointer as usize % alignment, 0);
                assert_global_owner(pointer);
                assert!(
                    std::slice::from_raw_parts(pointer, old.size())
                        .iter()
                        .all(|v| *v == 0)
                );
                std::slice::from_raw_parts_mut(pointer, old.size()).fill(0xa5);
                let grown = realloc(pointer, old, new.size());
                assert!(!grown.is_null());
                assert_eq!(grown as usize % alignment, 0);
                assert_global_owner(grown);
                assert!(
                    std::slice::from_raw_parts(grown, old.size())
                        .iter()
                        .all(|v| *v == 0xa5)
                );
                dealloc(grown, new);
            }
        }
    }

    #[test]
    fn libc_system_allocations_keep_their_owner() {
        let layout = Layout::from_size_align(4096, 16).unwrap();
        // SAFETY: System.alloc is deliberately paired with System.dealloc.
        // This tests coexistence without passing a C allocation to MiMalloc.
        unsafe {
            let pointer = System.alloc(layout);
            assert!(!pointer.is_null());
            #[cfg(all(target_env = "musl", feature = "mimalloc"))]
            assert!(!mi_is_in_heap_region(pointer.cast()));
            pointer.write(42);
            assert_eq!(pointer.read(), 42);
            System.dealloc(pointer, layout);
        }
    }

    #[test]
    fn cross_thread_free_and_thread_exit_preserve_data() {
        let (sender, receiver) = std::sync::mpsc::sync_channel::<(usize, Vec<u8>)>(8);
        let consumer = std::thread::spawn(move || {
            let mut total = 0;
            for (index, bytes) in receiver {
                assert_global_owner(bytes.as_ptr());
                assert!(bytes.iter().all(|v| *v == index as u8));
                total += bytes.len();
            }
            total
        });
        let mut expected = 0;
        for index in 1..1024 {
            let bytes = vec![index as u8; 1 + index % 8192];
            expected += bytes.len();
            sender.send((index, bytes)).unwrap();
        }
        drop(sender);
        assert_eq!(consumer.join().unwrap(), expected);
        for _ in 0..8 {
            let workers: Vec<_> = (0..4)
                .map(|_| std::thread::spawn(|| vec![0x42_u8; 16384]))
                .collect();
            for worker in workers {
                let bytes = worker.join().unwrap();
                assert_global_owner(bytes.as_ptr());
                assert!(bytes.iter().all(|v| *v == 0x42));
            }
        }
    }
}
