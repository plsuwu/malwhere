use windows::Win32::Foundation::{HANDLE, UNICODE_STRING};
use windows::Win32::System::WindowsProgramming::CLIENT_ID;

#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SYSTEM_THREAD_INFORMATION {
    /// ```no_run
    /// // index 0
    /// pub Reserved1: [i64; 3]
    /// ```
    pub KernelTime: i64,
    /// ```no_run
    /// // index 1
    /// pub Reserved1: [i64; 3]
    /// ```
    pub UserTime: i64,
    /// ```no_run
    /// // index 2
    /// pub Reserved1: [i64; 3]
    /// ```
    pub CreateTime: i64,
    /// ```no_run
    /// pub Reserved2: u32
    /// ```
    pub WaitTime: u32,
    pub StartAddress: *mut core::ffi::c_void,
    pub ClientId: CLIENT_ID,
    pub Priority: i32,
    pub BasePriority: i32,
    /// ```no_run
    /// pub Reserved3: u32
    /// ```
    pub ContextSwitches: u32,
    pub ThreadState: u32,
    pub WaitReason: u32,
}

/// Extension of Windows' `SYSTEM_PROCESS_INFORMATION` struct.
///
/// This custom `SYSTEM_PROCESS_INFORMATION` struct contains the undocumented `Threads` field
/// (to more easily obtain its array entries) along with a handful of other undocumented
/// `Reserved` fields.
///
/// # Usage
///
/// The `SYSTEM_PROCESS_INFORMATION` struct is a linked list, with the `NextEntryOffset` field
/// describing the number of bytes to the next node.
///
/// ```no_run
/// // create a heap-allocated buffer to read in raw struct bytes
/// let mut bytes: Vec<u8> = Vec::new();
/// let mut read_byte_count = 0;    // optional; can be `null_mut()`
///
/// // returns NTSTATUS - 0x0 == STATUS_SUCCESS
/// _STATUS = NtQuerySystemInformation(
///     SystemProcessInformation,
///     bytes.as_ptr() as _,
///     0,
///     &mut read_byte_count
/// ).unwrap();
///
/// // cast raw bytes to `SYSTEM_PROCESS_INFORMATION` struct
/// let head_ptr =
///     bytes.as_ptr() as *mut _ as *const SYSTEM_PROCESS_INFORMATION;
///
///
/// let mut node = head_ptr;
/// let mut next =
///     node.byte_add((*node).NextEntryOffset as usize);
///
/// // ...
/// ```
///
/// ## `Threads` field
///
/// While this field technically references as array, its layout in-memory is a little strange in
/// that it seems each index is mapped directly to the end of this struct - also note that it
/// appears to sometimes reference `NULL` or protected regions.
///
/// In practice, this means the "true" number of `SYSTEM_THREAD_INFORMATION` array items is not
/// always referenced in the `NumberOfThreads` field.
///
/// The simplest solution here is to only enumerate threads for specific target processes.
///
/// ```no_run
/// // dereference the list entry pointer
/// let node: SYSTEM_PROCESS_INFORMATION = *node_ptr;
///
/// // locate a target process
/// if (*node).ImageName.Length != 0 &&
///     &node
///         .ImageName
///         .Buffer
///         .to_string()
///         .unwrap() == "calc.exe"
///     {
///         // cast `Threads` field to a pointer for Rust pointer
///         // arithmetic operators
///         let threads_head =
///             (&node.Threads) as *const _ as *mut SYSTEM_THREAD_INFORMATION;
///
///         for index in node.NumberOfThreads {
///
///             // note that this new pointer may sometimes reference
///             // NULL or otherwise unreadable data!
///             let thread_info = *threads_head.add(index as usize);
///             println!("{:#?}", thread_info);
///         }
///     }
/// ```
#[allow(non_snake_case, non_camel_case_types)]
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct SYSTEM_PROCESS_INFORMATION {
    pub NextEntryOffset: u32,
    pub NumberOfThreads: u32,

    /// ```no_run
    /// // idx 0 -> 7 (8 bytes)
    /// pub Reserved1: [u8; 48]
    /// ```
    pub WorkingSetPrivateSize: i64,

    /// ```no_run
    /// // idx 8 -> 11 (4 bytes)
    /// pub Reserved1: [u8; 48]
    /// ```
    pub HardFaultCount: u32,

    /// ```no_run
    /// // idx 12 -> 15 (4 bytes)
    /// pub Reserved1: [u8; 48]
    /// ```
    pub NumberOfThreadsHighWatermark: u32,

    /// ```no_run
    /// // idx 16 -> 23 (8 bytes)
    /// pub Reserved1: [u8; 48]
    /// ```
    pub CycleTime: u64,

    /// ```no_run
    /// // idx 24 -> 31 (8 bytes)
    /// pub Reserved1: [u8; 48]
    /// ```
    pub CreateTime: i64,

    /// ```no_run
    /// // idx 32 -> 39 (8 bytes)
    /// pub Reserved1: [u8; 48]
    /// ```
    pub UserTime: i64,

    /// ```no_run
    /// // idx 40 -> 47 (8 bytes)
    /// pub Reserved1: [u8; 48]
    /// ```
    pub KernelTime: i64,

    pub ImageName:UNICODE_STRING,
    pub BasePriority: i32,
    pub UniqueProcessId: HANDLE,

    /// ```no_run
    /// // MS type `HANDLE`
    /// pub Reserved2: *mut core::ffi::c_void
    /// ```
    pub InheritedFromUniqueProcessId: *mut core::ffi::c_void,

    pub HandleCount: u32,
    pub SessionId: u32,

    /// ```no_run
    /// // MS type `ULONG_PTR`
    /// pub Reserved3: *mut core::ffi::c_void
    /// ```
    pub UniqueProcessKey: *mut core::ffi::c_void,

    pub PeakVirtualSize: usize,
    pub VirtualSize: usize,

    /// ```no_run
    /// // MS type `ULONG`
    /// pub Reserved4: u32
    /// ```
    pub PageFaultCount: u32,

    pub PeakWorkingSetSize: usize,
    pub WorkingSetSize: usize,

    /// ```no_run
    /// // MS type `SIZE_T`
    /// pub Reserved5: *mut core::ffi::c_void
    /// ```
    pub QuotePeakPagedPoolUsage: usize,

    pub QuotaPagedPoolUsage: usize,

    /// ```no_run
    /// // MS type `SIZE_T`
    /// pub Reserved6: *mut core::ffi::c_void
    /// ```
    pub QuotePeakNonPagedPoolUsage: usize,

    pub QuotaNonPagedPoolUsage: usize,
    pub PagefileUsage: usize,
    pub PeakPagefileUsage: usize,
    pub PrivatePageCount: usize,

    /// ```no_run
    /// // index 0
    /// pub Reserved7: [i64; 6]
    /// ```
    pub ReadOperationCount: i64,
    /// ```no_run
    /// // index 1
    /// pub Reserved7: [i64; 6]
    /// ```
    pub WriteOperationCount: i64,
    /// ```no_run
    /// // index 2
    /// pub Reserved7: [i64; 6]
    /// ```
    pub OtherOperationCount: i64,
    /// ```no_run
    /// // index 3
    /// pub Reserved7: [i64; 6]
    /// ```
    pub ReadTransferCount: i64,
    /// ```no_run
    /// // index 4
    /// pub Reserved7: [i64; 6]
    /// ```
    pub WriteTransferCount: i64,
    /// ```no_run
    /// // index 5
    /// pub Reserved7: [i64; 6]
    /// ```
    pub OtherTransferCount: i64,
    /// ```no_run
    /// // C/C++ type
    /// SYSTEM_THREAD_INFORMATION Thread[1];
    /// ```
    pub Threads: SYSTEM_THREAD_INFORMATION,
}
