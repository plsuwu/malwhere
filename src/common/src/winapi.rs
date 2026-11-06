#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]


pub type BOOL = i32;
pub type WCHAR = u16;
pub type PWCHAR = *mut WCHAR;


pub type HANDLE = *mut core::ffi::c_void;
pub type DWORD = u32;
pub type SIZE_T = usize;

pub type PVOID = *mut core::ffi::c_void;
pub type LPVOID = *const core::ffi::c_void;

pub type HEAP_FLAGS = u32;
pub const HEAP_ZERO_MEMORY: DWORD = 0x00000008;

#[link(name = "kernel32.dll")]
unsafe extern "C" {
    /// Retrieves a handle to the default heap of the calling process. This handle can then be used
    /// in subsequent calls to the heap functions.
    pub fn GetProcessHeap() -> HANDLE;

    /// Allocates a block of memory from a heap. The allocated memory is not movable.
    pub fn HeapAlloc(hHeap: HANDLE, dwFlags: DWORD, dwBytes: SIZE_T) -> LPVOID;

    /// Reallocates a block of memory from a heap. This function enables you to resize a memory
    /// block and change other memory block properties. The allocated memory is not movable.
    pub fn HeapReAlloc(hHeap: HANDLE, dwFlags: DWORD, lpMem: LPVOID, dwBytes: SIZE_T) -> LPVOID;

    /// Frees a memory block allocated from a heap by the `HeapAlloc` or `HeapReAlloc` function.
    pub fn HeapFree(hHeap: HANDLE, dwFlags: DWORD, lpMem: LPVOID) -> BOOL;
}
