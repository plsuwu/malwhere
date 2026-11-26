#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]

use bitflags::bitflags;

pub type BYTE = u8;
pub type CHAR = i8;
pub type WCHAR = u16;
pub type USHORT = u16;
pub type WORD = u16;
pub type ULONG = u32;
pub type UINT = u32;
pub type DWORD = u32;
pub type DWORD64 = u64;
pub type HEAP_FLAGS = u32;
pub type BOOL = i32;
pub type LONG = i32;
pub type ULONGLONG = u64;
pub type LONGLONG = i64;
pub type SIZE_T = usize;
pub type ULONG_PTR = usize;
pub type INT_PTR = isize;

pub type HANDLE = *mut core::ffi::c_void;
pub type PVOID = *mut core::ffi::c_void;
pub type LPVOID = *mut core::ffi::c_void;
pub type LPCVOID = *const core::ffi::c_void;

pub type PULONG = *mut ULONG;
pub type PWSTR = *mut WCHAR;
pub type LPCWSTR = *const WCHAR;
pub type PWCHAR = *mut WCHAR;
pub type PWORD = *mut WORD;
pub type PDWORD = *mut DWORD;
pub type LPDWORD = *mut DWORD;
pub type PHANDLE = *mut HANDLE;

pub type PPS_POST_PROCESS_INIT_ROUTINE = Option<unsafe extern "system" fn()>;

pub const IMAGE_DOS_SIGNATURE: USHORT = 0x5A4D;
pub const IMAGE_NT_SIGNATURE: DWORD = 0x00004550;

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: WORD = 0;
pub const IMAGE_DIRECTORY_ENTRY_IMPORT: WORD = 1;
pub const IMAGE_DIRECTORY_ENTRY_RESOURCE: WORD = 2;
pub const IMAGE_DIRECTORY_ENTRY_EXCEPTION: WORD = 3;
pub const IMAGE_DIRECTORY_ENTRY_SECURITY: WORD = 4;
pub const IMAGE_DIRECTORY_ENTRY_BASERELOC: WORD = 5;
pub const IMAGE_DIRECTORY_ENTRY_DEBUG: WORD = 6;
pub const IMAGE_DIRECTORY_ENTRY_GLOBALPTR: WORD = 8;
pub const IMAGE_DIRECTORY_ENTRY_TLS: WORD = 9;
pub const IMAGE_DIRECTORY_ENTRY_IAT: WORD = 12;

pub const HEAP_ZERO_MEMORY: DWORD = 0x00000008;
pub const MAX_PATH: u32 = 260;

pub const INVALID_HANDLE_VALUE: HANDLE = (-1i64).cast_unsigned() as _;
pub const STD_INPUT_HANDLE: DWORD = (-10i32).cast_unsigned();
pub const STD_OUTPUT_HANDLE: DWORD = (-11i32).cast_unsigned();
pub const STD_ERROR_HANDLE: DWORD = (-12i32).cast_unsigned();

pub const CONTEXT_DEBUG_REGISTERS: DWORD = 0x100010;

pub type FARPROC = Option<unsafe extern "system" fn() -> INT_PTR>;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_EXPORT_DIRECTORY {
    pub Characteristics: DWORD,
    pub TimeDateStamp: DWORD,
    pub MajorVersion: WORD,
    pub MinorVersion: WORD,
    pub Name: DWORD,
    pub Base: DWORD,
    pub NumberOfFunctions: DWORD,
    pub NumberOfNames: DWORD,
    pub AddressOfFunctions: DWORD,
    pub AddressOfNames: DWORD,
    pub AddressOfNameOrdinals: DWORD,
}

pub type PIMAGE_EXPORT_DIRECTORY = *mut IMAGE_EXPORT_DIRECTORY;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_DOS_HEADER {
    pub e_magic: WORD,
    pub e_cblp: WORD,
    pub e_cp: WORD,
    pub e_crlc: WORD,
    pub e_cparhdr: WORD,
    pub e_minalloc: WORD,
    pub e_maxalloc: WORD,
    pub e_ss: WORD,
    pub e_sp: WORD,
    pub e_csum: WORD,
    pub e_ip: WORD,
    pub e_cs: WORD,
    pub e_lfarlc: WORD,
    pub e_ovno: WORD,
    pub e_res: [WORD; 4],
    pub e_oemid: WORD,
    pub e_oeminfo: WORD,
    pub e_res2: [WORD; 10],
    pub e_lfanew: LONG,
}

pub type PIMAGE_DOS_HEADER = *mut IMAGE_DOS_HEADER;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_NT_HEADERS {
    pub Signature: DWORD,
    pub FileHeader: IMAGE_FILE_HEADER,
    pub OptionalHeader: IMAGE_OPTIONAL_HEADER,
}

pub type PIMAGE_NT_HEADERS = *mut IMAGE_NT_HEADERS;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_DATA_DIRECTORY {
    pub VirtualAddress: DWORD,
    pub Size: DWORD,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IMAGE_OPTIONAL_HEADER {
    pub Magic: WORD,
    pub MajorLinkerVersion: BYTE,
    pub MinorLinkerVersion: BYTE,
    pub SizeOfCode: DWORD,
    pub SizeOfInitializedData: DWORD,
    pub SizeOfUninitializedData: DWORD,
    pub AddressOfEntryPoint: DWORD,
    pub BaseOfCode: DWORD,
    pub ImageBase: ULONGLONG,
    pub SectionAlignment: DWORD,
    pub FileAlignment: DWORD,
    pub MajorOperatingSystemVersion: WORD,
    pub MinorOperatingSystemVersion: WORD,
    pub MajorImageVersion: WORD,
    pub MinorImageVersion: WORD,
    pub MajorSubsystemVersion: WORD,
    pub MinorSubsystemVersion: WORD,
    pub Win32VersionValue: DWORD,
    pub SizeOfImage: DWORD,
    pub SizeOfHeaders: DWORD,
    pub CheckSum: DWORD,
    pub Subsystem: WORD,
    pub DllCharacteristics: WORD,
    pub SizeOfStackReserve: ULONGLONG,
    pub SizeOfStackCommit: ULONGLONG,
    pub SizeOfHeapReserve: ULONGLONG,
    pub SizeOfHeapCommit: ULONGLONG,
    pub LoaderFlags: DWORD,
    pub NumberOfRvaAndSizes: DWORD,
    pub DataDirectory: [IMAGE_DATA_DIRECTORY; 16],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IMAGE_FILE_HEADER {
    pub Machine: WORD,
    pub NumberOfSections: WORD,
    pub TimeDateStamp: DWORD,
    pub PointerToSymbolTable: DWORD,
    pub NumberOfSymbols: DWORD,
    pub SizeOfOptionalHeader: WORD,
    pub Characteristics: WORD,
}

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

/// Constructed from [NtDoc `PEB_LDR_DATA`] documentation.
///
/// [NtDoc `PEB_LDR_DATA`]: https://ntdoc.m417z.com/peb_ldr_data
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PEB_LDR_DATA {
    pub Length: ULONG,
    pub Initialized: BYTE,
    pub SsHandle: HANDLE,
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
    pub EntryInProgress: PVOID,
    pub ShutdownInProgress: BYTE,
    pub ShutdownThreadId: HANDLE,
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

/// Header of a serialized activation context data blob.
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ACTIVATION_CONTEXT_DATA {
    pub Magic: ULONG,
    pub HeaderSize: ULONG,
    pub FormatVersion: ULONG,
    pub TotalSize: ULONG,
    /// Byte offset to `ACTIVATION_CONTEXT_DATA_TOC_HEADER` from this structure's base.
    pub DefaultTocOffset: ULONG,
    /// Byte offset to `ACTIVATION_CONTEXT_DATA_EXTENDED_TOC_HEADER` from this structure's base; zero if absent.
    pub ExtendedTocOffset: ULONG,
    /// Byte offset to `ACTIVATION_CONTEXT_DATA_ASSEMBLY_ROSTER_HEADER` from this structure's base.
    pub AssemblyRosterOffset: ULONG,
    /// `ACTIVATION_CONTEXT_FLAG_*` flags.
    pub Flags: ULONG,
}

pub type PACTIVATION_CONTEXT_DATA = *mut ACTIVATION_CONTEXT_DATA;

#[repr(C)]
#[derive(Clone, Copy)]
pub union PEB_0 {
    /// Pointer to the switchback compatibility engine (Windows 7 and below).
    pub pContextData: PVOID,
    /// Pointer to the EC bitmap on ARM64 (Windows 11 and above).
    pub EcCodeBitMap: PVOID,
}

#[repr(C)]
pub struct RTL_BITMAP {
    pub SizeOfBitMap: ULONG,
    pub Buffer: PULONG,
}

pub type PRTL_BITMAP = *mut RTL_BITMAP;

#[repr(C)]
pub struct API_SET_NAMESPACE {
    pub Version: ULONG,
    pub Size: ULONG,
    pub Flags: ULONG,
    pub Count: ULONG,
    pub EntryOffset: ULONG,
    pub HashOffset: ULONG,
    pub HashFactor: ULONG,
}

pub type PAPI_SET_NAMESPACE = *mut API_SET_NAMESPACE;

#[repr(C)]
#[derive(Clone, Copy)]
pub union LARGE_INTEGER {
    pub Anonymous: LARGE_INTEGER_0,
    pub u: LARGE_INTEGER_1,
    pub QuadPart: LONGLONG,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LARGE_INTEGER_0 {
    pub LowPart: DWORD,
    pub HighPart: LONG,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct LARGE_INTEGER_1 {
    pub LowPart: DWORD,
    pub HighPart: LONG,
}

impl Default for LARGE_INTEGER {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union ULARGE_INTEGER {
    pub Anonymous: ULARGE_INTEGER_0,
    pub u: ULARGE_INTEGER_1,
    pub QuadPart: ULONGLONG,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ULARGE_INTEGER_0 {
    pub LowPart: DWORD,
    pub HighPart: DWORD,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct ULARGE_INTEGER_1 {
    pub LowPart: DWORD,
    pub HighPart: DWORD,
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

    #[repr(transparent)]
    #[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
    pub struct NT_GLOBAL_FLAGS: ULONG {
        const FLG_STOP_ON_EXCEPTION           = 1 << 0;  // 0x00000001
        const FLG_SHOW_LDR_SNAPS              = 1 << 1;  // 0x00000002
        const FLG_DEBUG_INITIAL_COMMAND       = 1 << 2;  // 0x00000004
        const FLG_STOP_ON_HUNG_GUI            = 1 << 3;  // 0x00000008
        const FLG_HEAP_ENABLE_TAIL_CHECK      = 1 << 4;  // 0x00000010
        const FLG_HEAP_ENABLE_FREE_CHECK      = 1 << 5;  // 0x00000020
        const FLG_HEAP_VALIDATE_PARAMETERS    = 1 << 6;  // 0x00000040
        const FLG_HEAP_VALIDATE_ALL           = 1 << 7;  // 0x00000080
        const FLG_APPLICATION_VERIFIER        = 1 << 8;  // 0x00000100
        const FLG_MONITOR_SILENT_PROCESS_EXIT = 1 << 9;  // 0x00000200
        const FLG_POOL_ENABLE_TAGGING         = 1 << 10; // 0x00000400
        const FLG_HEAP_ENABLE_TAGGING         = 1 << 11; // 0x00000800
        const FLG_USER_STACK_TRACE_DB         = 1 << 12; // 0x00001000
        const FLG_KERNEL_STACK_TRACE_DB       = 1 << 13; // 0x00002000
        const FLG_MAINTAIN_OBJECT_TYPELIST    = 1 << 14; // 0x00004000
        const FLG_HEAP_ENABLE_TAG_BY_DLL      = 1 << 15; // 0x00008000
        const FLG_DISABLE_STACK_EXTENSION     = 1 << 16; // 0x00010000
        const FLG_ENABLE_CSRDEBUG             = 1 << 17; // 0x00020000
        const FLG_ENABLE_KDEBUG_SYMBOL_LOAD   = 1 << 18; // 0x00040000
        const FLG_DISABLE_PAGE_KERNEL_STACKS  = 1 << 19; // 0x00080000
        const FLG_ENABLE_SYSTEM_CRIT_BREAKS   = 1 << 20; // 0x00100000
        const FLG_HEAP_DISABLE_COALESCING     = 1 << 21; // 0x00200000
        const FLG_ENABLE_CLOSE_EXCEPTIONS     = 1 << 22; // 0x00400000
        const FLG_ENABLE_EXCEPTION_LOGGING    = 1 << 23; // 0x00800000
        const FLG_ENABLE_HANDLE_TYPE_TAGGING  = 1 << 24; // 0x01000000
        const FLG_HEAP_PAGE_ALLOCS            = 1 << 25; // 0x02000000
        const FLG_DEBUG_INITIAL_COMMAND_EX    = 1 << 26; // 0x04000000
        const FLG_DISABLE_DBGPRINT            = 1 << 27; // 0x08000000
        const FLG_CRITSEC_EVENT_CREATION      = 1 << 28; // 0x10000000
        const FLG_LDR_TOP_DOWN                = 1 << 29; // 0x20000000
        const FLG_ENABLE_HANDLE_EXCEPTIONS    = 1 << 30; // 0x40000000
        const FLG_DISABLE_PROTDLLS            = 1 << 31; // 0x80000000

        // heap flags set by the loader when a process is started under a debugger (i.e. 0x70)
        const FLG_DEBUGGER_HEAP = Self::FLG_HEAP_ENABLE_TAIL_CHECK.bits()
                                | Self::FLG_HEAP_ENABLE_FREE_CHECK.bits()
                                | Self::FLG_HEAP_VALIDATE_PARAMETERS.bits();
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

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SYSTEMTIME {
    pub wYear: WORD,
    pub wMonth: WORD,
    pub wDayOfWeek: WORD,
    pub wDay: WORD,
    pub wHour: WORD,
    pub wMinute: WORD,
    pub wSecond: WORD,
    pub wMilliseconds: WORD,
}

pub type LPSYSTEMTIME = *mut SYSTEMTIME;
pub type PSYSTEMTIME = *mut SYSTEMTIME;

#[repr(transparent)]
pub struct NTSTATUS(pub i32);

#[repr(C)]
pub struct SRWLOCK {
    pub ptr: *mut core::ffi::c_void,
}

#[link(name = "kernel32", kind = "raw-dylib")]
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
    pub fn ExitProcess(uExitCode: UINT) -> !;

    /// Creates an anonymous pipe, and returns handles to the read and write ends of the pipe.
    pub fn CreatePipe(
        hReadPipe: PHANDLE,
        hWritePipe: PHANDLE,
        lpPipeAttributes: LPSECURITY_ATTRIBUTES,
        nSize: DWORD,
    ) -> BOOL;

    pub fn AddVectoredExceptionHandler(First: ULONG, Handler: PVECTORED_EXCEPTION_HANDLER)
    -> PVOID;

    /// Closes an open object handle.
    pub fn CloseHandle(hObject: HANDLE) -> BOOL;

    /// Retrieves the current value of the performance counter, which is a high resolution (<1us)
    /// time stamp that can be used for time-interval measurements.
    pub fn QueryPerformanceCounter(lpPerformanceCount: *mut LARGE_INTEGER) -> BOOL;

    /// Opens an existing local process object.
    pub fn OpenProcess(dwDesiredAccess: DWORD, bInheritHandle: BOOL, dwProcessId: DWORD) -> HANDLE;

    /// Retrieves the calling thread's last-error code value. The last-error code is maintained on
    /// a per-thread basis. Multiple threads do not overwrite each other's last-error code.
    pub fn GetLastError() -> DWORD;
}

pub type PCONTEXT = *mut CONTEXT;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EXCEPTION_POINTERS {
    pub ExceptionRecord: PEXCEPTION_RECORD,
    pub ContextRecord: PCONTEXT,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EXCEPTION_RECORD {
    pub ExceptionCode: DWORD,
    pub ExceptionFlags: DWORD,
    pub ExceptionRecord: *mut Self,
    pub ExceptionAddress: PVOID,
    pub NumberParameters: DWORD,
    pub ExceptionInformation: [ULONG_PTR; 15],
}

pub type PEXCEPTION_RECORD = *mut EXCEPTION_RECORD;
pub type PVECTORED_EXCEPTION_HANDLER =
    unsafe extern "system" fn(exceptioninfo: *mut EXCEPTION_POINTERS) -> LONG;

pub const BCRYPT_USE_SYSTEM_PREFERRED_RNG: u32 = 0x0000_0002;
pub const SYSTEM_PREFERRED_ALG_HANDLE: BCRYPT_ALG_HANDLE = BCRYPT_ALG_HANDLE(core::ptr::null_mut());

#[link(name = "bcrypt", kind = "raw-dylib")]
unsafe extern "system" {
    /// The BCryptGenRandom function generates a random number.
    pub fn BCryptGenRandom(
        hAlgorithm: BCRYPT_ALG_HANDLE,
        pbBuffer: *mut BYTE,
        cbBuffer: ULONG,
        dwFlags: ULONG,
    ) -> i32;
}

#[repr(transparent)]
pub struct BCRYPT_ALG_HANDLE(pub *mut core::ffi::c_void);

/// Constructed from [NtDoc `PEB`] types and documentation.
///
/// [NtDoc `PEB`]: https://ntdoc.m417z.com/peb
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PEB {
    /// The process was cloned with an inherited address space.
    pub InheritedAddressSpace: BYTE,
    /// The process has image file execution options (IFEO).
    pub ReadImageFileExecOptions: BYTE,
    /// The process has a debugger attached.
    pub BeingDebugged: BYTE,
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
    /// Pointer to the process default heap (`PHEAP`)
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
    pub Reserved7: PVOID,
    /// Reserved.
    pub SystemReserved: ULONG,
    /// Pointer to the Active Template Library (ATL) singly linked list (32-bit)
    pub AtlThunkSListPtr32: ULONG,
    /// Pointer to the API Set Schema.
    pub ApiSetMap: PAPI_SET_NAMESPACE,
    /// Counter for TLS expansion.
    pub TlsExpansionCounter: ULONG,
    /// Pointer to the TLS bitmap.
    pub TlsBitmap: PRTL_BITMAP,
    /// Bits for the TLS bitmap.
    pub TlsBitmapBits: [ULONG; 2],
    /// Reserved for CSRSS.
    pub ReadOnlySharedMemoryBase: PVOID,
    /// Pointer to the USER_SHARED_DATA for the current SILO (`PSILO_USER_SHARED_DATA`)
    pub SharedData: PVOID,
    /// Reserved for CSRSS.
    pub ReadOnlyStaticServerData: *mut PVOID,
    /// Pointer to the ANSI code page data (`PCPTABLEINFO`)
    pub AnsiCodePageData: PVOID,
    /// Pointer to the OEM code page data (`PCPTABLEINFO`)
    pub OemCodePageData: PVOID,
    /// Pointer to the Unicode case table data (`PNLSTABLEINFO`).
    pub UnicodeCaseTableData: PVOID,
    /// The total number of system processors.
    pub NumberOfProcessors: ULONG,
    /// Global flags for the system.
    pub NtGlobalFlags: NT_GLOBAL_FLAGS,
    /// Timeout for critical sections.
    pub CriticalSectionTimeout: LARGE_INTEGER,
    /// Reserved size for heap segments.
    pub HeapSegmentReserve: SIZE_T,
    /// Committed size for heap segments.
    pub HeapSegmentCommit: SIZE_T,
    /// Threshold for decommitting total free heap.
    pub HeapDeCommitTotalFreeThreshold: SIZE_T,
    /// Threshold for decommitting free heap blocks.
    pub HeapDeCommitFreeBlockThreshold: SIZE_T,
    /// Number of process heaps.
    pub NumberOfHeaps: ULONG,
    /// Maximum number of process heaps.
    pub MaximumNumberOfHeaps: ULONG,
    /// Pointer to an array of process heaps. `ProcessHeaps` is initialized to point to the first
    /// free byte after the PEB and `MaximumNumberOfHeaps` is computed from the page size used to
    /// hold the PEB, less the fixed size of this data structure.
    pub ProcessHeaps: *mut PVOID,
    /// Pointer to the system GDI shared handle table.
    pub GdiSharedHandleTable: PVOID,
    /// Pointer to the process starter helper.
    pub ProcessStarterHelper: PVOID,
    /// The maximum number of GDI function calls during batch operations (`GdiSetBatchLimit`).
    pub GdiDCAttributeList: ULONG,
    /// Pointer to the loader lock critical section.
    pub LoaderLock: PRTL_CRITICAL_SECTION,
    /// Major version of the operating system.
    pub OSMajorVersion: ULONG,
    /// Minor version of the operating system.
    pub OSMinorVersion: ULONG,
    /// Build number of the operating system.
    pub OSBuildNumber: USHORT,
    /// CSD version of the operating system.
    pub OSCSDVersion: USHORT,
    /// Platform ID of the operating system.
    pub OSPlatformId: ULONG,
    /// Subsystem version of the current process image (PE Headers).
    pub ImageSubsystem: ULONG,
    /// Major version of the current process image subsystem (PE Headers).
    pub ImageSubsystemMajorVersion: ULONG,
    /// Minor version of the current process image subsystem (PE Headers).
    pub ImageSubsystemMinorVersion: ULONG,
    /// Affinity mask for the current process.
    pub ActiveProcessorAffinityMask: ULONG_PTR,
    /// Temporary buffer for GDI handles accumulated in the current batch.
    pub GdiHandleBuffer: [ULONG; 60],
    /// Pointer to the post-process initialization routine available for use by the application.
    pub PostProcessInitRoutine: PPS_POST_PROCESS_INIT_ROUTINE,
    /// Pointer to the TLS expansion bitmap.
    pub TlsExpansionBitmap: PRTL_BITMAP,
    /// Bits for the TLS expansion bitmap (`TLS_EXPANSION_SLOTS`).
    pub TlsExpansionBitmapBits: [ULONG; 32],
    /// Session ID of the current process.
    pub SessionId: ULONG,
    /// Application compatibility flags (`KACF_*`).
    pub AppCompatFlags: ULARGE_INTEGER,
    /// Application compatibility flags (`KACF_*`).
    pub AppCompatFlagsUser: ULARGE_INTEGER,
    /// Pointer to the Application SwitchBack Compatibility Engine (`PSHIM_PROCESS_CONTEXT`).
    pub pShimData: PVOID,
    /// Pointer to the Application Compatibility Engine (`PAPPCOMPAT_EXE_DATA`).
    pub AppCompatInfo: PVOID,
    /// CSD version string of the operating system.
    pub CSDVersion: UNICODE_STRING,
    /// Pointer to the process activation context.
    pub ActivationContextData: PACTIVATION_CONTEXT_DATA,
    /// Pointer to the process assembly storage map (`PASSEMBLY_STORAGE_MAP`).
    pub ProcessAssemblyStorageMap: PVOID,
    /// Pointer to the system default activation context.
    pub SystemDefaultActivationContextData: PACTIVATION_CONTEXT_DATA,
    /// Pointer to the system assembly storage map (`PASSEMBLY_STORAGE_MAP`).
    pub SystemAssemblyStorageMap: PVOID,
    /// Minimum stack commit size.
    pub MinimumStackCommit: SIZE_T,
    /// Spare pointers (previously `FlsCallback` through `FlsHighIndex` before 19H1).
    pub SparePointers: [PVOID; 2],
    /// Pointer to the patch loader data (`PLDR_PATCH_TABLE`).
    pub PatchLoaderData: PVOID,
    /// Pointer to the CHPE V2 process information (`CHPEV2_PROCESS_INFO`).
    pub ChpeV2ProcessInfo: PVOID,
    /// Packaged process feature state.
    pub AppModelFeatureState: ULONG,
    pub SpareUlongs: [ULONG; 2],
    /// Active code page.
    pub ActiveCodePage: USHORT,
    /// OEM code page.
    pub OemCodePage: USHORT,
    /// Code page case mapping.
    pub UseCaseMapping: USHORT,
    /// Unused NLS field.
    pub UnusedNlsField: USHORT,
    /// Pointer to the application WER registration data (`PWER_PEB_HEADER_BLOCK`).
    pub WerRegistrationData: PVOID,
    /// Pointer to the application WER assert pointer (`PWER_REGISTRATION_DATA`).
    pub WerShipAssertPtr: PVOID,
    /// Switchback compatibility engine context or ARM64 EC bitmap.
    pub Anonymous: PEB_0,
    /// Reserved.
    pub ImageHeaderHash: PVOID,
    /// ETW tracing flags.
    pub TracingFlags: ULONG,
    /// Reserved for CSRSS.
    pub CsrServerReadOnlySharedMemoryBase: ULONGLONG,
    /// Thread pool worker list lock (`PRTL_SRWLOCK`).
    pub TppWorkerpListLock: PVOID,
    /// Thread pool worker list.
    pub TppWorkerpList: LIST_ENTRY,
    /// Wait on address hash table (`RtlWaitOnAddress`).
    pub WaitOnAddressHashTable: [PVOID; 128],
    /// Pointer to the telemetry coverage header (`PTELEMETRY_COVERAGE_HEADER`); since RS3.
    pub TelemetryCoverageHeader: PVOID,
    /// Cloud file flags (ProjFs and Cloud Files); since RS4.
    pub CloudFileFlags: ULONG,
    /// Cloud file diagnostic flags.
    pub CloudFileDiagFlags: ULONG,
    /// Placeholder compatibility mode (ProjFs and Cloud Files).
    pub PlaceholderCompatibilityMode: CHAR,
    /// Reserved for placeholder compatibility mode.
    pub PlaceholderCompatibilityModeReserved: [CHAR; 7],
    /// Pointer to leap second data (`PLEAP_SECOND_DATA`); since RS5.
    pub LeapSecondData: PVOID,
    /// Leap second flags.
    pub LeapSecondFlags: ULONG,
    /// Global flags for the process.
    pub NtGlobalFlags2: ULONG,
    /// Extended feature disable mask (AVX); since Windows 11.
    pub ExtendedFeatureDisableMask: ULONGLONG,
    /// Optional USER client process flags (`PCLIENTPROCINFO`), allocated by USER32.
    pub Win32ClientProcInfo: PVOID,
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct CONTEXT {
    pub P1Home: DWORD64,
    pub P2Home: DWORD64,
    pub P3Home: DWORD64,
    pub P4Home: DWORD64,
    pub P5Home: DWORD64,
    pub P6Home: DWORD64,
    pub ContextFlags: DWORD,
    pub MxCsr: DWORD,
    pub SegCs: WORD,
    pub SegDs: WORD,
    pub SegEs: WORD,
    pub SegFs: WORD,
    pub SegGs: WORD,
    pub SegSs: WORD,
    pub EFlags: DWORD,
    pub Dr0: DWORD64,
    pub Dr1: DWORD64,
    pub Dr2: DWORD64,
    pub Dr3: DWORD64,
    pub Dr6: DWORD64,
    pub Dr7: DWORD64,
    pub Rax: DWORD64,
    pub Rcx: DWORD64,
    pub Rdx: DWORD64,
    pub Rbx: DWORD64,
    pub Rsp: DWORD64,
    pub Rbp: DWORD64,
    pub Rsi: DWORD64,
    pub Rdi: DWORD64,
    pub R8: DWORD64,
    pub R9: DWORD64,
    pub R10: DWORD64,
    pub R11: DWORD64,
    pub R12: DWORD64,
    pub R13: DWORD64,
    pub R14: DWORD64,
    pub R15: DWORD64,
    pub Rip: DWORD64,
    pub Anonymous: CONTEXT_0,
    pub VectorRegister: [M128A; 26],
    pub VectorControl: DWORD64,
    pub DebugControl: DWORD64,
    pub LastBranchToRip: DWORD64,
    pub LastBranchFromRip: DWORD64,
    pub LastExceptionToRip: DWORD64,
    pub LastExceptionFromRip: DWORD64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub union CONTEXT_0 {
    pub FltSave: XMM_SAVE_AREA32,
    pub Anonymous: CONTEXT_0_0,
}

#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XSAVE_FORMAT {
    pub ControlWord: WORD,
    pub StatusWord: WORD,
    pub TagWord: BYTE,
    pub Reserved1: BYTE,
    pub ErrorOpcode: WORD,
    pub ErrorOffset: DWORD,
    pub ErrorSelector: WORD,
    pub Reserved2: WORD,
    pub DataOffset: DWORD,
    pub DataSelector: WORD,
    pub Reserved3: WORD,
    pub MxCsr: DWORD,
    pub MxCsr_Mask: DWORD,
    pub FloatRegisters: [M128A; 8],
    pub XmmRegisters: [M128A; 16],
    pub Reserved4: [BYTE; 96],
}

pub type XMM_SAVE_AREA32 = XSAVE_FORMAT;

#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CONTEXT_0_0 {
    pub Header: [M128A; 2],
    pub Legacy: [M128A; 8],
    pub Xmm0: M128A,
    pub Xmm1: M128A,
    pub Xmm2: M128A,
    pub Xmm3: M128A,
    pub Xmm4: M128A,
    pub Xmm5: M128A,
    pub Xmm6: M128A,
    pub Xmm7: M128A,
    pub Xmm8: M128A,
    pub Xmm9: M128A,
    pub Xmm10: M128A,
    pub Xmm11: M128A,
    pub Xmm12: M128A,
    pub Xmm13: M128A,
    pub Xmm14: M128A,
    pub Xmm15: M128A,
}

impl Default for XSAVE_FORMAT {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

#[repr(C, align(16))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct M128A {
    pub Low: ULONGLONG,
    pub High: LONGLONG,
}

impl Default for CONTEXT_0_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

impl Default for CONTEXT_0 {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

impl Default for CONTEXT {
    fn default() -> Self {
        unsafe { core::mem::zeroed() }
    }
}

/// Because I built the PEB struct by hand, these assertions should more or less ensure that fields
/// are at the right offset.
#[cfg(target_pointer_width = "64")]
const _: () = {
    use core::mem::{offset_of, size_of};

    assert!(size_of::<ACTIVATION_CONTEXT_DATA>() == 0x20);
    assert!(offset_of!(PEB, PostProcessInitRoutine) == 0x230);
    assert!(offset_of!(PEB, TlsExpansionBitmap) == 0x238);
    assert!(offset_of!(PEB, SessionId) == 0x2C0);
    assert!(offset_of!(PEB, AppCompatFlags) == 0x2C8);
    assert!(offset_of!(PEB, CSDVersion) == 0x2E8);
    assert!(offset_of!(PEB, WerRegistrationData) == 0x358);
    assert!(offset_of!(PEB, WaitOnAddressHashTable) == 0x3A0);
    assert!(offset_of!(PEB, Win32ClientProcInfo) == 0x7D0);
    assert!(size_of::<PEB>() == 0x7D8);
};
