#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use bitflags::bitflags;

pub type BYTE = u8;
pub type WCHAR = u16;
pub type USHORT = u16;
pub type WORD = u16;
pub type ULONG = u32;
pub type UINT = u32;
pub type DWORD = u32;
pub type HEAP_FLAGS = u32;
pub type BOOL = i32;
pub type LONG = i32;
pub type ULONGLONG = u64;
pub type SIZE_T = usize;
pub type ULONG_PTR = usize;
pub type INT_PTR = isize;

pub type HANDLE = *mut core::ffi::c_void;
pub type PVOID = *mut core::ffi::c_void;
pub type LPVOID = *mut core::ffi::c_void;
pub type LPCVOID = *const core::ffi::c_void;

pub type PWSTR = *mut WCHAR;
pub type PWCHAR = *mut WCHAR;
pub type PWORD = *mut WORD;
pub type PDWORD = *mut DWORD;
pub type LPDWORD = *mut DWORD;
pub type PHANDLE = *mut HANDLE;

pub type PPS_POST_PROCESS_INIT_ROUTINE = Option<unsafe extern "system" fn()>;

pub const HEAP_ZERO_MEMORY: DWORD = 0x00000008;
pub const MAX_PATH: u32 = 260;

pub const INVALID_HANDLE_VALUE: HANDLE = (-1i64).cast_unsigned() as _;
pub const STD_INPUT_HANDLE: DWORD = (-10i32).cast_unsigned();
pub const STD_OUTPUT_HANDLE: DWORD = (-11i32).cast_unsigned();
pub const STD_ERROR_HANDLE: DWORD = (-12i32).cast_unsigned();

pub type FARPROC = Option<unsafe extern "system" fn() -> INT_PTR>;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UNICODE_STRING {
    pub Length: USHORT,
    pub MaximumLength: USHORT,
    pub Buffer: PWSTR,
}

#[repr(C)]
pub struct SECURITY_ATTRIBUTES {
    pub nLength: DWORD,
    pub lpSecurityDescriptor: LPVOID,
    pub bInheritHandle: BOOL,
}

pub type LPSECURITY_ATTRIBUTES = *mut SECURITY_ATTRIBUTES;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct HINSTANCE__ {
    pub unused: i32,
}

pub type HMODULE = *mut HINSTANCE__;

#[repr(C)]
#[derive(Clone, Copy)]
pub union LDR_DATA_TABLE_ENTRY_0 {
    pub CheckSum: ULONG,
    pub Reserved6: PVOID,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LIST_ENTRY {
    pub Flink: *mut Self,
    pub Blink: *mut Self,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SINGLE_LIST_ENTRY {
    pub Next: *mut Self,
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub union SLIST_HEADER {
    pub Anonymous: SLIST_HEADER_0,
    pub HeaderX64: SLIST_HEADER_1,
}

pub type PSLIST_HEADER = *mut SLIST_HEADER;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SLIST_HEADER_0 {
    pub Alignment: ULONGLONG,
    pub Region: ULONGLONG,
}
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SLIST_HEADER_1 {
    pub _bitfield1: u64,
    pub _bitfield2: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub Reserved1: [PVOID; 2],
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub Reserved2: [PVOID; 2],
    pub DllBase: PVOID,
    pub Reserved3: [PVOID; 2],
    pub FullDllName: UNICODE_STRING,
    pub Reserved4: [BYTE; 8],
    pub Reserved5: [PVOID; 3],
    pub Anonymous: LDR_DATA_TABLE_ENTRY_0,
    pub TimeDateStamp: ULONG,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PEB_LDR_DATA {
    pub Reserved1: [BYTE; 8],
    pub Reserved2: [PVOID; 3],
    pub InMemoryOrderModuleList: LIST_ENTRY,
}

pub type PPEB_LDR_DATA = *mut PEB_LDR_DATA;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub Reserved1: [BYTE; 16],
    pub Reserved2: [PVOID; 10],
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,
}

pub type PRTL_USER_PROCESS_PARAMETERS = *mut RTL_USER_PROCESS_PARAMETERS;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PEB {
    /// The process was cloned with an inherited address space.
    ///
    /// ```c,no_run
    /// BYTE Reserved1[2]; /* @ idx = 0 */
    /// ```
    pub InheritedAddressSpace: BYTE,
    /// The process has image file execution options (IFEO).
    ///
    /// ```c
    /// BYTE Reserved1[2]; /* @ idx = 1 */
    /// ```
    pub ReadImageFileExecOptions: BYTE,
    /// The process has a debugger attached.
    pub BeingDebugged: BYTE,
    /// Because we use `bitflags` for this bitfield union, the usage is a bit different:
    ///
    /// ```
    /// // assumes we have dereferenced a valid PEB pointer
    /// let peb: PEB = /* .. PEB retrieval logic .. */;
    /// let is_protected = peb.BitField.contains(BIT_FIELD::IsProtectedProcess);
    /// ```
    pub BitField: BIT_FIELD,
    /// Handle to a mutex for synchronization.
    pub Mutant: HANDLE,
    /// Pointer to the base address of the process image.
    pub ImageBaseAddress: PVOID,
    /// Pointer to the process loader data.
    pub Ldr: PPEB_LDR_DATA,
    /// Pointer to the process parameters.
    pub ProcessParameters: PRTL_USER_PROCESS_PARAMETERS,
    /// Reserved.
    pub SubSystemData: PVOID,
    /// Pointer to the process default heap.
    ///
    /// NOTE: Technically a `PHEAP` (i.e. pointer to a `HEAP` struct)
    ///  * https://github.com/winsiderss/systeminformer/blob/29d2104f1634331e178f70d172239583d1c14bc8/SystemInformer/include/heapstruct.h#L126
    pub ProcessHeap: PVOID,
    /// Pointer to a critical section used to synchronize access to the PEB.
    pub FastPebLock: PRTL_CRITICAL_SECTION,
    /// Pointer to a singly linked list used by ATL.
    pub AtlThunkSListPtr: PSLIST_HEADER,
    /// Handle to the Image File Execution Options key.
    pub IFEOKey: HANDLE,
    /// Cross process flags.
    pub CrossProcessFlags: CROSS_PROCESS_FLAGS,
    /// User32 KERNEL_CALLBACK_TABLE (ntuser.h)
    /// ```c
    /// union {
    ///     PKERNEL_CALLBACK_TABLE KernelCallbackTable;
    ///     PVOID UserSharedInfoPtr;
    /// };
    /// ```
    pub Reserved7: PVOID,
    /// Reserved.
    pub SystemReserved: ULONG,
    /// Pointer to the Active Template Library (ATL) singly linked list (32-bit)
    pub AtlThunkSListPtr32: ULONG,
    pub Reserved9: [PVOID; 45],
    pub Reserved10: [BYTE; 96],
    /// Pointer to the post-process initialization routine available for use by the application.
    pub PostProcessInitRoutine: PPS_POST_PROCESS_INIT_ROUTINE,
    pub Reserved11: [BYTE; 128],
    pub Reserved12: [PVOID; 1],
    /// Session ID of the current process.
    pub SessionId: ULONG,

    // ... additional fields after `SessionId`; see:
    //  * https://ntdoc.m417z.com/peb#:~:text=%2F%2F%20Session%20ID%20of%20the%20current%20process
}

bitflags! {
    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct BIT_FIELD: BYTE {
        /// The process uses large image regions (4 MB).
        const ImageUsesLargePages = 1 << 0;
        /// The process is a protected process.
        const IsProtectedProcess = 1 << 1;
        /// The process image base address was relocated.
        const IsImageDynamicallyRelocated = 1 << 2;
        /// The process skipped forwarders for User32.dll functions. 1 for 64-bit, 0 for 32-bit.
        const SkipPatchingUser32Forwarders = 1 << 3;
        /// The process is a packaged store process (APPX/MSIX).
        const IsPackagedProcess = 1 << 4;
        /// The process has an AppContainer token.
        const IsAppContainerProcess = 1 << 5;
        /// The process is a protected process (light).
        const IsProtectedProcessLight = 1 << 6;
        /// The process is long path-aware.
        const IsLongPathAwareProcess = 1 << 7;
    }

    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
    pub struct CROSS_PROCESS_FLAGS: ULONG {
        /// The process is part of a job.
        const ProcessInJob = 1 << 0;
        /// The process is initializing.
        const ProcessInitializing = 1 << 1;
        /// The process is using VEH.
        const ProcessUsingVEH = 1 << 2;
        /// The process is using VCH.
        const ProcessUsingVCH = 1 << 3;
        /// The process is using FTH.
        const ProcessUsingFTH = 1 << 4;
        /// The process was previously throttled.
        const ProcessPreviouslyThrottled = 1 << 5;
        /// The process is currently throttled.
        const ProcessCurrentlyThrottled = 1 << 6;
        /// The process images are hot patched. // RS5
        const ProcessImagesHotPatched = 1 << 7;
        /// ReservedBits0 : 24;
        const _ = !0;
    }
}

impl CROSS_PROCESS_FLAGS {
    /// ReservedBits0
    #[inline]
    pub const fn ReservedBits0(self) -> u32 {
        self.bits() >> 8
    }
}

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

#[repr(C, packed(8))]
#[derive(Clone, Copy, Default)]
pub struct RTL_CRITICAL_SECTION {
    pub DebugInfo: PRTL_CRITICAL_SECTION_DEBUG,
    pub LockCount: LONG,
    pub RecursionCount: LONG,
    pub OwningThread: HANDLE,
    pub LockSemaphore: HANDLE,
    pub SpinCount: ULONG_PTR,
}

pub type PRTL_CRITICAL_SECTION = *mut RTL_CRITICAL_SECTION;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct _RTL_CRITICAL_SECTION_DEBUG {
    pub Type: WORD,
    pub CreatorBackTraceIndex: WORD,
    pub CriticalSection: *mut RTL_CRITICAL_SECTION,
    pub ProcessLocksList: LIST_ENTRY,
    pub EntryCount: DWORD,
    pub ContentionCount: DWORD,
    pub Flags: DWORD,
    pub CreatorBackTraceIndexHigh: WORD,
    pub Identifier: WORD,
}

pub type PRTL_CRITICAL_SECTION_DEBUG = *mut _RTL_CRITICAL_SECTION_DEBUG;

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
