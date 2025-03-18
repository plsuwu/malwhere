#![allow(non_snake_case, non_camel_case_types)]

use core::ffi::c_void;
use windows::Win32::Foundation::UNICODE_STRING;
use windows::Win32::System::Kernel::{LIST_ENTRY, STRING};
// use windows::Win32::System::WindowsProgramming::*;

const RTL_MAX_DRIVE_LETTERS: usize = 32;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct PEB_LDR_DATA {
    pub Length: u32,
    pub Initialized: u32,

    /// ```ignore
    /// // idx [0]
    /// pub Reserved2: [*mut c_void; 3],
    /// ```
    pub SsHandle: *mut c_void,

    /// ```ignore
    /// // idx [1]
    /// pub Reserved2: [*mut c_void; 3],
    /// ```
    pub InLoadOrderModuleList: *mut c_void,

    /// ```ignore
    /// // idx [2]
    /// pub Reserved2: [*mut c_void; 3],
    /// ```
    pub InInitializationOrderModuleList: *mut c_void,
    pub InMemoryOrderModuleList: LIST_ENTRY,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct LDR_MODULE {
    pub InLoadOrderModuleList: LIST_ENTRY,
    pub InMemoryOrderModuleList: LIST_ENTRY,
    pub InInitializationOrderModuleList: LIST_ENTRY,
    pub BaseAddress: *mut c_void,
    pub EntryPoint: *mut c_void,
    pub SizeOfImage: u32,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    pub Flags: u32,
    pub LoadCount: i16,
    pub TlsIndex: i16,
    pub HashTableEntry: LIST_ENTRY,
    pub TimeDateStamp: u32,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq)]
/// Not sure how correct the fields in this struct are, I don't really want
/// to test every single one at the moment (my apologies) but it generally seems aligned.
///
/// > Some of the pointers might be `*mut *mut c_void`/`*mut *mut *mut c_void` instead of
/// > just `*mut c_void` but I'm not sure whether that affects this struct's alignment.
pub struct PROCESS_ENVIRONMENT_BLOCK {
    pub InheritedAddressSpace: u8,
    pub ReadImageFileExecOptions: u8,

    pub BeingDebugged: u8,
    pub Spare: u8,
    pub Mutant: *mut c_void,
    pub ImageBase: *mut c_void,
    pub LoaderData: *mut PEB_LDR_DATA,
    pub ProcessParameters: *mut RTL_USER_PROCESS_PARAMETERS,
    pub SubSystemData: *mut c_void,
    pub ProcessHeap: *mut c_void,
    pub FastPebLock: *mut c_void,
    pub FastPebLockRoutine: *mut c_void,
    pub FastPebUnlockRoutine: *mut c_void,
    pub EnvironmentUpdateCount: u32,
    /// This type was originally:
    /// ```ignore
    /// PVOID *KernelCallbackTable;
    /// ```
    /// Pointer is technically `*mut *mut c_void`
    /// > i.e, Ptr->Ptr->Data
    pub KernelCallbackTable: *mut c_void,
    pub EventLogSection: *mut c_void,
    pub EventLog: *mut c_void,
    pub FreeList: *mut c_void,
    pub TlsExpansionCounter: u32,
    pub TlsBitmap: *mut c_void,
    pub TlsBitmapBits: [u32; 0x2],
    pub ReadOnlySharedMemoryBase: *mut c_void,
    pub ReadOnlySharedMemoryHeap: *mut c_void,
    /// This type was originally:
    /// ```ignore
    /// PVOID *ReadOnlyStaticServerData;
    /// ```
    /// Pointer is technically `*mut *mut c_void`
    /// > i.e, Ptr->Ptr->Data
    pub ReadOnlyStaticServerData: *mut c_void,
    pub AnsiCodePageData: *mut c_void,
    pub OemCodePageData: *mut c_void,
    pub UnicodeCaseTableData: *mut c_void,
    pub NumberOfProcessors: u32,
    pub NtGlobalFlag: u32,
    pub Spare2: [u8; 0x4],
    pub CriticalSectionTimeout: i64,
    pub HeapSegmentReserve: u32,
    pub HeapSegmentCommit: u32,
    pub HeapDeCommitTotalFreeThreshold: u32,
    pub HeapDeCommitFreeBlockThreshold: u32,
    pub NumberOfHeaps: u32,
    pub MaximumNumberOfHeaps: u32,
    /// This type was originally:
    /// ```ignore
    /// PVOID **ProcessHeaps;
    /// ```
    /// Pointer is technically `*mut *mut *mut c_void`
    /// > i.e, Ptr->Ptr->Ptr->Data
    pub ProcessHeaps: *mut c_void,
    pub GdiSharedHandleTable: *mut c_void,
    pub ProcessStarterHelper: *mut c_void,
    pub GdiDCAttributeList: *mut c_void,
    pub LoaderLock: *mut c_void,
    pub OSMajorVersion: u32,
    pub OSMinorVersion: u32,
    pub OSBuildNumber: u32,
    pub OSPlatformId: u32,
    pub ImageSubSystem: u32,
    pub ImageSubSystemMajorVersion: u32,
    pub ImageSubSystemMinorVersion: u32,
    pub GdiHandleBuffer: [u32; 0x22],
    pub PostProcessInitRoutine: u32,
    pub TlsExpansionBitmap: u32,
    pub TlsExpansionBitmapBits: [u8; 0x80],
    pub SessionId: u32,
}

#[repr(C)]
pub union LDR_DATA_TABLE_ENTRY_u1 {
    pub InInitializationOrderLinks: LIST_ENTRY,
    pub InProgressLinks: LIST_ENTRY,
}

#[repr(C)]
pub union LDR_DATA_TABLE_ENTRY_u2 {
    pub FlagGroup: [u8; 4],
    pub Flags: u32,
}

#[repr(C)]
pub struct ACTIVATION_CONTEXT {
    pub dummy: *mut c_void,
}

pub type PLDR_INIT_ROUTINE = Option<
    unsafe extern "system" fn(
        DllHandle: *mut c_void,
        Reason: u32, Context: *mut c_void
    ) -> u8,
>;

/// This is technically incomplete but some of the later field types depend on other (large) types,
/// and it's a recursive nightmare to implement completely.
///
/// I've cut it off where the `windows-rs` implementation ends, but this should generally be
/// suitable for our requirements.
#[repr(C)]
pub struct LDR_DATA_TABLE_ENTRY {
    pub InLoadOrderLinks: LIST_ENTRY,
    pub InMemoryOrderLinks: LIST_ENTRY,
    pub u1: LDR_DATA_TABLE_ENTRY_u1,
    pub DllBase: *mut c_void,
    pub EntryPoint: PLDR_INIT_ROUTINE,
    pub SizeOfImage: u32,
    pub FullDllName: UNICODE_STRING,
    pub BaseDllName: UNICODE_STRING,
    pub u2: LDR_DATA_TABLE_ENTRY_u2,
    pub ObsoleteLoadCount: u16,
    pub TlsIndex: u16,
    pub HashLinks: LIST_ENTRY,
    pub TimeDateStamp: u32,
}

#[repr(C)]
pub struct CURDIR {
    pub DosPath: UNICODE_STRING,
    pub Handle: *mut c_void,
}

#[repr(C)]
pub struct RTL_DRIVE_LETTER_CURDIR {
    pub Flags: u16,
    pub Length: u16,
    pub TimeStamp: u32,
    pub DosPath: STRING,
}


#[repr(C)]
pub struct RTL_USER_PROCESS_PARAMETERS {
    pub MaximumLength: u32,
    pub Length: u32,
    pub Flags: u32,
    pub DebugFlags: u32,
    pub ConsoleHandle: *mut c_void,
    pub ConsoleFlags: u32,
    pub StandardInput: *mut c_void,
    pub StandardOutput: *mut c_void,
    pub StandardError: *mut c_void,

    pub CurrentDirectory: CURDIR,
    pub DllPath: UNICODE_STRING,
    pub ImagePathName: UNICODE_STRING,
    pub CommandLine: UNICODE_STRING,

    /// PBYTE
    pub Environment: *mut u16,

    pub StartingX: u32,
    pub StartingY: u32,
    pub CountX: u32,
    pub CountY: u32,
    pub CountCharsX: u32,
    pub CountCharsY: u32,
    pub FillAttribute: u32,

    pub WindowFlags: u32,
    pub ShowWindowFlags: u32,
    pub WindowTitle: UNICODE_STRING,
    pub DesktopInfo: UNICODE_STRING,
    pub ShellInfo: UNICODE_STRING,
    pub RuntimeData: UNICODE_STRING,
    pub CurrentDirectories: [RTL_DRIVE_LETTER_CURDIR; RTL_MAX_DRIVE_LETTERS],

    pub EnvironmentSize: usize,
    pub EnvironmentVersion: usize,

    pub PackageDependencyData: *mut c_void,
    pub ProcessGroupId: u32,
    pub LoaderThreads: u32,
    pub RedirectDllName: UNICODE_STRING,
    pub HeapPartitionName: UNICODE_STRING,
    pub DefaultThreadpoolCpuSetMasks: *mut u64,
    pub DefaultThreadpoolCpuSetMaskCount: u32,
    pub DefaultThreadpoolThreadMaximum: u32,
    pub HeapMemoryTypeMask: u32,
}