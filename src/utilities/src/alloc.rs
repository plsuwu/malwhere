extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use core::ffi::c_void;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};

pub const HEAP_ZERO_MEMORY: u32 = 0x0000_0008;

#[link(name = "kernel32")]
unsafe extern "system" {
    pub fn GetProcessHeap() -> *mut c_void;
    pub fn HeapAlloc(hHeap: *mut c_void, dwFlags: u32, dwBytes: usize) -> *mut c_void;
    pub fn HeapFree(hHeap: *mut c_void, dwFlags: u32, lpMem: *mut c_void) -> i32;
    pub fn HeapReAlloc(
        hHeap: *mut c_void,
        dwFlags: u32,
        lpMem: *mut c_void,
        dwBytes: usize,
    ) -> *mut c_void;
}

pub struct WinHeap {
    heap: AtomicPtr<c_void>,
}

impl WinHeap {
    pub const fn new() -> Self {
        WinHeap {
            heap: AtomicPtr::new(ptr::null_mut()),
        }
    }

    #[inline]
    fn handle(&self) -> *mut c_void {
        let mut h = self.heap.load(Ordering::Relaxed);
        if h.is_null() {
            h = unsafe { GetProcessHeap() };
            self.heap.store(h, Ordering::Relaxed);
        }
        h
    }

    #[inline]
    unsafe fn alloc_impl(&self, layout: Layout, flags: u32) -> *mut u8 {
        let align = layout.align();
        let header = core::mem::size_of::<usize>();
        let total = match layout
            .size()
            .checked_add(align)
            .and_then(|v| v.checked_add(header))
        {
            Some(t) => t,
            None => return ptr::null_mut(),
        };

        let base = unsafe { HeapAlloc(self.handle(), flags, total) } as usize;
        if base == 0 {
            return ptr::null_mut();
        }

        let unaligned = base + header;
        let aligned = (unaligned + align - 1) & !(align - 1);

        unsafe { ptr::write((aligned as *mut usize).offset(-1), base) };

        aligned as *mut u8
    }

    #[inline]
    unsafe fn real_base(ptr: *mut u8) -> *mut c_void {
        (unsafe { ptr::read((ptr as *mut usize).offset(-1)) }) as *mut c_void
    }
}

impl Default for WinHeap {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl GlobalAlloc for WinHeap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { self.alloc_impl(layout, 0) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        unsafe { self.alloc_impl(layout, HEAP_ZERO_MEMORY) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _: Layout) {
        if ptr.is_null() {
            return;
        }

        unsafe { HeapFree(self.handle(), 0, Self::real_base(ptr)) };
    }

    // unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
    //     if ptr.is_null() {
    //         return unsafe {
    //             self.alloc(Layout::from_size_align_unchecked(new_size, layout.align()))
    //         };
    //     }
    //     (unsafe { HeapReAlloc(self.handle(), 0, ptr as *mut c_void, new_size) }) as *mut u8
    // }

    // unsafe fn realloc(&self, ptr: *mut u8, _: Layout, new_size: usize) -> *mut u8 {
    //     (unsafe { HeapReAlloc(self.handle(), 0, ptr as *mut c_void, new_size) }) as *mut u8
    // }
}

#[global_allocator]
static ALLOCATOR: WinHeap = WinHeap::new();
