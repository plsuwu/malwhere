#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

use crate::winapi;

/// Alignment `HeapAlloc` guarantees (`MEMORY_ALLOCATION_ALIGNMENT`)
#[cfg(target_pointer_width = "64")] // 64-bit
const MIN_ALIGN: usize = 16;

// #[cfg(target_pointer_width = "32")] // 32-bit
// const MIN_ALIGN: usize = 8;

pub struct WinHeap;

static HEAP: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(ptr::null_mut());

#[inline]
fn heap() -> *mut core::ffi::c_void {
    let proc_heap = HEAP.load(Ordering::Relaxed);
    if proc_heap.is_null() {
        let proc_heap = unsafe { winapi::GetProcessHeap() };
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

#[global_allocator]
static ALLOCATOR: WinHeap = WinHeap;
