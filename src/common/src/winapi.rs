#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

pub type BOOL = i32;
pub type UINT = u32;
pub type DWORD = u32;
pub type HEAP_FLAGS = u32;
pub type WCHAR = u16;
pub type SIZE_T = usize;
pub type ULONG_PTR = usize;

pub type HANDLE = *mut core::ffi::c_void;
pub type PVOID = *mut core::ffi::c_void;
pub type LPVOID = *mut core::ffi::c_void;
pub type LPCVOID = *const core::ffi::c_void;

pub type PWCHAR = *mut WCHAR;
pub type LPDWORD = *mut DWORD;
pub type PHANDLE = *mut HANDLE;

pub const HEAP_ZERO_MEMORY: DWORD = 0x00000008;

pub const INVALID_HANDLE_VALUE: HANDLE = (-1i64).cast_unsigned() as _;
pub const STD_INPUT_HANDLE: DWORD = (-10i32).cast_unsigned();
pub const STD_OUTPUT_HANDLE: DWORD = (-11i32).cast_unsigned();
pub const STD_ERROR_HANDLE: DWORD = (-12i32).cast_unsigned();

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OVERLAPPED_0_0 {
    pub Offset: DWORD,
    pub OffsetHigh: DWORD,
}

#[repr(C)]
pub union OVERLAPPED_0 {
    pub Anonymous: OVERLAPPED_0_0,
    pub Pointer: PVOID,
}

#[repr(C)]
pub struct OVERLAPPED {
    pub Internal: ULONG_PTR,
    pub InternalHigh: ULONG_PTR,
    pub u: OVERLAPPED_0,
    pub hEvent: HANDLE,
}

pub type LPOVERLAPPED = *mut OVERLAPPED;

#[repr(C)]
pub struct SECURITY_ATTRIBUTES {
    pub nLength: DWORD,
    pub lpSecurityDescriptor: LPVOID,
    pub bInheritHandle: BOOL,
}

pub type LPSECURITY_ATTRIBUTES = *mut SECURITY_ATTRIBUTES;

#[link(name = "kernel32")]
unsafe extern "system" {
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

    /// Validates the specified heap.
    ///
    /// The function scans all the memory blocks in the heap and verifies that the heap control
    /// structures maintained by the heap manager are in a consistent state. You can also use the
    /// `HeapValidate` function to validate a single memory block within a specified heap without
    /// checking the validity of the entire heap.
    pub fn HeapValidate(hHeap: HANDLE, dwFlags: DWORD, lpMem: LPCVOID) -> BOOL;

    /// Retrieves the size of a memory block allocated from a heap by the `HeapAlloc` or
    /// `HeapReAlloc` function.
    pub fn HeapSize(hHeap: HANDLE, dwFlags: DWORD, lpMem: LPCVOID) -> SIZE_T;

    /// Writes data to the specified file or input/output (I/O) device.
    ///
    /// This function is designed for both synchronous and asynchronous operation. For a similar
    /// function designed solely for asynchronous operation, see `WriteFileEx`.
    pub fn WriteFile(
        hFile: HANDLE,
        lpBuffer: LPCVOID,
        nNumberOfBytesToWrite: DWORD,
        lpNumberOfBytesWritten: LPDWORD,
        lpOverlapped: LPOVERLAPPED,
    ) -> BOOL;

    /// Reads data from the specified file or input/output (I/O) device. Reads occur at the 
    /// position specified by the file pointer if supported by the device.
    ///
    /// This function is designed for both synchronous and asynchronous operations. For a similar
    /// function designed solely for asynchronous operation, see ReadFileEx.
    pub fn ReadFile(
        hFile: HANDLE,
        lpBuffer: LPVOID,
        nNumberOfBytesToRead: DWORD,
        lpNumberOfBytesToRead: LPDWORD,
        lpOverlapped: LPOVERLAPPED,
    ) -> BOOL;

    /// Retrieves a handle to the specified standard device (standard input, standard output, or
    /// standard error).
    ///
    /// The `nStdHandle` parameter can be one of:
    ///    * `STD_INPUT_HANDLE`
    ///    * `STD_OUTPUT_HANDLE`
    ///    * `STD_ERROR_HANDLE`
    pub fn GetStdHandle(nStdHandle: DWORD) -> HANDLE;

    /// Sets the handle for the specified standard device (standard input, standard output, or
    /// standard error).
    ///
    /// The `nStdHandle` parameter can be one of:
    ///    * `STD_INPUT_HANDLE`
    ///    * `STD_OUTPUT_HANDLE`
    ///    * `STD_ERROR_HANDLE`
    pub fn SetStdHandle(nStdHandle: DWORD, hHandle: HANDLE) -> BOOL;

    /// Ends the calling process and all its threads.
    pub fn ExitProcess(uExitCode: UINT);

    /// Creates an anonymous pipe, and returns handles to the read and write ends of the pipe.
    pub fn CreatePipe(
        hReadPipe: PHANDLE,
        hWritePipe: PHANDLE,
        lpPipeAttributes: LPSECURITY_ATTRIBUTES,
        nSize: DWORD,
    ) -> BOOL;

    /// Closes an open object handle.
    pub fn CloseHandle(hObject: HANDLE) -> BOOL;
}
