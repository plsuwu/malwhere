#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::winapi;

/// Alignment guaranteed by `HeapAlloc` (`MEMORY_ALLOCATION_ALIGNMENT`)
#[cfg(target_pointer_width = "64")]
const MIN_ALIGN: usize = 16;

pub struct WinHeap;

static HEAP: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(ptr::null_mut());

#[inline]
fn heap() -> *mut core::ffi::c_void {
    let mut proc_heap = HEAP.load(Ordering::Relaxed);
    if proc_heap.is_null() {
        proc_heap = unsafe { winapi::GetProcessHeap() };
        HEAP.store(proc_heap, Ordering::Relaxed);
    }

    proc_heap
}

#[inline]
unsafe fn alloc_impl(layout: Layout, flags: winapi::HEAP_FLAGS) -> *mut u8 {
    if layout.align() <= MIN_ALIGN {
        return unsafe { winapi::HeapAlloc(heap(), flags, layout.size()) as *mut u8 };
    }

    let Some(total) = layout.size().checked_add(layout.align()) else {
        return ptr::null_mut();
    };

    let raw = unsafe { winapi::HeapAlloc(heap(), flags, total) as *mut u8 };
    if raw.is_null() {
        return raw;
    }

    let offset = layout.align() - (raw as usize & (layout.align() - 1));
    let aligned = unsafe { raw.add(offset) };
    unsafe { (aligned as *mut *mut u8).sub(1).write(raw) };

    aligned
}

unsafe impl GlobalAlloc for WinHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { alloc_impl(layout, 0x00) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { alloc_impl(layout, winapi::HEAP_ZERO_MEMORY) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        let raw = if layout.align() <= MIN_ALIGN {
            ptr
        } else {
            unsafe { (ptr as *mut *mut u8).sub(1).read() }
        };
        let ok = unsafe { winapi::HeapFree(heap(), 0x00, raw as winapi::LPVOID) };
        debug_assert!(ok != 0x00, "HeapFree fail");
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if layout.align() <= MIN_ALIGN {
            return unsafe {
                winapi::HeapReAlloc(heap(), 0x00, ptr as winapi::LPVOID, new_size) as *mut u8
            };
        }

        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        let new_ptr = unsafe { self.alloc(new_layout) };
        if !new_ptr.is_null() {
            unsafe {
                ptr::copy_nonoverlapping(ptr, new_ptr, layout.size().min(new_size));
                self.dealloc(ptr, layout);
            }
        }
        new_ptr
    }
}

#[cfg(test)]
mod test {
    extern crate alloc;

    use alloc::boxed::Box;
    use alloc::vec;
    use alloc::vec::Vec;

    use crate::{alloc::WinHeap, winapi};

    #[global_allocator]
    static GLOBAL: WinHeap = WinHeap;

    /// Returns `true` if the pointer `p` is the start of a live block in the process heap
    fn owned_by_process_heap(p: *const u8) -> bool {
        unsafe {
            let heap = winapi::GetProcessHeap();
            winapi::HeapValidate(heap, 0x00, p as *const core::ffi::c_void) != 0
                && winapi::HeapSize(heap, 0x00, p as *const core::ffi::c_void) != usize::MAX
        }
    }

    #[test]
    fn allocations_are_from_process_heap() {
        let b = Box::new([0u8; 100]);
        assert!(owned_by_process_heap(b.as_ptr()));
    }

    #[test]
    fn alloc_and_realloc() {
        let mut v: Vec<u64> = (0..1000).collect();

        // repeated growth should `realloc`
        v.extend(1000..100_000);
        assert_eq!(v.iter().sum::<u64>(), 99_999 * 100_000 / 2);
        assert!(owned_by_process_heap(v.as_ptr().cast()));

        // `(..).shrink_to_fit()` should also `realloc`
        v.truncate(10);
        v.shrink_to_fit();
        assert_eq!(v, [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
    }

    #[test]
    fn zeroed() {
        // allocates using `alloc_zeroed` (i think)
        let z = vec![0u8; 1 << 20];
        assert!(z.iter().all(|&b| b == 0));
    }

    #[test]
    fn over_aligned() {
        #[repr(align(4096))]
        struct Page([u8; 4096]);

        let pages: Vec<Box<Page>> = (0..16).map(|_| Box::new(Page([7; 4096]))).collect();
        for p in &pages {
            assert_eq!(&**p as *const Page as usize % 4096, 0, "bad alignment");
            assert!(p.0.iter().all(|&b| b == 7));
        }
    }

    #[test]
    fn many_thread() {
        // need `std::thread` and idk how to set `no_std` only when `#[cfg(not(test))]`
        extern crate std;

        let handles: Vec<_> = (0..8)
            .map(|t| {
                std::thread::spawn(move || {
                    let mut v = Vec::new();
                    for i in 0..50_000u64 {
                        v.push(i * t);
                    }
                    v.iter().sum::<u64>()
                })
            })
            .collect();

        for (t, h) in handles.into_iter().enumerate() {
            assert_eq!(h.join().unwrap(), t as u64 * 49_999 * 50_000 / 2);
        }
    }
}
