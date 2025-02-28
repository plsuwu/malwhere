use crate::environment_block::read_gs::GetBlock;
use crate::environment_block::types::{
    LDR_DATA_TABLE_ENTRY, PEB_LDR_DATA, PROCESS_ENVIRONMENT_BLOCK,
};
use lazy_static::lazy_static;
use std::ffi::{c_void, CStr};
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
};

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
const SYSCALL_OPCODES: [u8; 6] = [
    0x4c,
    0x8b,
    0xd1,
    0xb8,
    0x00,
    0x00,
];

const HOOKED_OPCODE: u8 = 0xe9;
const DOWN: i8 = 32;
const UP: i8 = -32;

// we probably don't want to hold this in memory for too long, so we might want to
// impl `Drop` for our `PROCESS_ENVIRONMENT_BLOCK` and `std::mem::zeroed()` its fields when
// it leaves scope?
lazy_static! {
    static ref GLOBAL_PEB: PROCESS_ENVIRONMENT_BLOCK = PROCESS_ENVIRONMENT_BLOCK::get();
}

unsafe impl Sync for PEB_LDR_DATA {}
unsafe impl Send for PEB_LDR_DATA {}

unsafe impl Sync for PROCESS_ENVIRONMENT_BLOCK {}
unsafe impl Send for PROCESS_ENVIRONMENT_BLOCK {}

#[repr(C)]
#[derive(Debug)]
/// Initializes relative virtual addresses (RVAs) for the module's exported function arrays
/// alongside some helpful metadata
///
/// # Usage
///
/// Initialization is facilitated by passing the module's base address (`module_base`) and the
/// virtual address of the module's export directory (`exports_base`):
///
/// ```ignore
/// let module_exports = ModuleExports::new(
///     // e.g `DllBase` of `ntdll.dll`,
///     module_base,
///     // address for `IMAGE_EXPORT_DIRECTORY`
///     // in `ntdll.dll`
///     exports_base,
///
/// );
///
/// // use initialized fields
/// println!(
///     "number of function names -> {}",
///     module_exports.names_count
/// );
/// ```
///
/// Make sure to dereference an RVA's pointer ***after*** applying an index to it, but ***before***
/// using it to resolve the 'true' pointer from the module's base address - for example, the 220th
/// name in the array of function names would be resolved as follows:
///
/// ```ignore
/// // apply the array indexing first
/// let idx: isize = 220;
///
/// // `idx` offsets the `rva_ptr` by `size_of::<u32>()`
/// // as it needs to create values equivalent to C
/// // `PDWORD *name_rva_ptr = names_addr[5];`:
/// let rva_ptr = module_exports
///     .names_array
///     .offset(idx);
///
/// // *const u32 (address) -> u32 (RVA);
/// // i.e, the RVA pointer must be dereferenced to
/// // get the RVA
/// let rva = *rva_ptr;
///
/// // apply RVA as an offset to `module_base` to retrieve
/// // the pointer to the element at `idx`:
/// let name_ptr = module_base
///     .byte_offset(rva as isize);
///
/// let name_str = CStr::from_ptr(name_ptr as *mut i8)
///     .to_str()
///     .unwrap();
///
/// // (this occasionally varies from version to version)
/// assert_eq!(name_str, "NtAllocateVirtualMemoryEx");
/// ```
pub struct ModuleExports {
    pub names_count: u32,
    pub funcs_count: u32,
    pub names_array: *mut u32,
    pub addrs_array: *mut u32,
    pub ordls_array: *mut u16,
    pub export_directory: *mut IMAGE_EXPORT_DIRECTORY,
}

impl ModuleExports {
    pub fn new(
        module_base: *mut c_void,
        export_addr: *mut IMAGE_EXPORT_DIRECTORY,
    ) -> anyhow::Result<Self> {
        // these two counts usually only differ slightly (some functions do not have
        // exported names)
        let names_count = unsafe { (*export_addr).NumberOfNames };
        let funcs_count = unsafe { (*export_addr).NumberOfFunctions };

        let names_array = unsafe {
            let rva = (*export_addr).AddressOfNames as isize;
            module_base.byte_offset(rva) as *mut u32
        };

        let addrs_array = unsafe {
            let rva = (*export_addr).AddressOfFunctions as isize;
            module_base.offset(rva) as *mut u32
        };

        let ordls_array = unsafe {
            let rva = (*export_addr).AddressOfNameOrdinals as isize;
            module_base.byte_offset(rva) as *mut u16
        };

        Ok(Self {
            names_count,
            funcs_count,
            names_array,
            addrs_array,
            ordls_array,
            export_directory: export_addr,
        })
    }

    pub fn read_name(&self, module_base: *mut c_void, index: isize) -> anyhow::Result<String> {
        let rva = unsafe { *self.names_array.offset(index) };
        let name =
            unsafe { CStr::from_ptr(module_base.byte_offset(rva as isize) as *mut i8).to_str()? };

        Ok(name.to_string())
    }

    pub fn get_function(&self, module_base: *mut c_void, index: isize) -> anyhow::Result<*mut c_void> {

        let ord_index = unsafe { *self.ordls_array.offset(index) };
        let fn_rva = unsafe { *self.addrs_array.offset(ord_index as isize) };
        let fn_address = unsafe { module_base.byte_add(fn_rva as usize) };

        Ok(fn_address)
    }

    pub fn get_ssn(&self, address: *mut c_void) -> anyhow::Result<u32> {
        let mut ssn = 0xff;

        let func_bytes: [u8; 6] = unsafe {[
            *((address as u64) as *const u8),
            *((address as u64 + 1) as *const u8),
            *((address as u64 + 2) as *const u8),
            *((address as u64 + 3) as *const u8),
            *((address as u64 + 6) as *const u8),
            *((address as u64 + 7) as *const u8),
        ]};



        if func_bytes == SYSCALL_OPCODES {
            let hi = unsafe { *((address as u64 + 5) as *const u8) };
            let lo = unsafe { *((address as u64 + 4) as *const u8) };
            ssn = hi.wrapping_shl(8) | lo;
        }

        if ssn != 0xff {
            return Ok(ssn as u32)
        };

        Err(anyhow::anyhow!("[x] Couldn't validate SSN."))
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct Module {
    pub module_base: *mut c_void,
    pub exports: ModuleExports,
}

impl Module {
    /// Retrieve base address of `ntdll.dll` via its offset from `ProcessEnvironmentBlock`
    /// `LoaderData` field
    pub fn ntdll() -> anyhow::Result<Self> {
        // bail if Windows version < 10
        // (note "Windows 10" also refers to Windows 11 here)
        if GLOBAL_PEB.OSMajorVersion != 0xA {
            Err(anyhow::anyhow!(
                "[x] Windows version '{}' invalid (expected '{}').",
                GLOBAL_PEB.OSMajorVersion,
                0xA,
            ))?
        }

        // resolve `LIST_ENTRY` for `ntdll.dll` using an offset and retrieve module's
        // base address
        let loader_entry = unsafe {
            (*(*GLOBAL_PEB.LoaderData).InMemoryOrderModuleList.Flink)
                .Flink
                .byte_offset(-0x10) as *mut LDR_DATA_TABLE_ENTRY
        };
        let module_base = unsafe { (*loader_entry).DllBase };

        // confirm our location and carve out exports directory
        let nt_headers = Self::get_headers(module_base as _)?;
        let export_addr = Self::get_exports(module_base as _, nt_headers)?;

        let exports = ModuleExports::new(module_base, export_addr)?;
        Ok(Self {
            module_base,
            exports,
        })
    }

    /// Resolves the module's `IMAGE_EXPORT_DIRECTORY` using its base address and
    /// `IMAGE_NT_HEADERS`
    pub fn get_exports(
        module_base: *mut c_void,
        nt_headers: *mut IMAGE_NT_HEADERS64,
    ) -> anyhow::Result<*mut IMAGE_EXPORT_DIRECTORY> {
        unsafe {
            let rva = (*nt_headers).OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]
                .VirtualAddress;
            let export_directory =
                module_base.byte_offset(rva as isize) as *mut IMAGE_EXPORT_DIRECTORY;
            Ok(export_directory)
        }
    }

    /// Retrieves NT headers of a PE file
    ///
    /// Also verifies DOS + NT header signatures to confirm expected position in the
    /// module
    fn get_headers(module_base: *mut c_void) -> anyhow::Result<*mut IMAGE_NT_HEADERS64> {
        // verify dos header ('MZ')
        let dos_header = module_base as *mut IMAGE_DOS_HEADER;
        if (unsafe { *dos_header }).e_magic != IMAGE_DOS_SIGNATURE {
            Err(anyhow::anyhow!(
                "[x] IMAGE_DOS_SIGNATURE '{:?}' invalid (expected {:?}).",
                unsafe { *dos_header }.e_magic,
                IMAGE_DOS_SIGNATURE,
            ))?
        }

        // verify nt headers ('PE\0\0')
        let nt_headers = unsafe {
            module_base.byte_offset((*dos_header).e_lfanew as isize) as *mut IMAGE_NT_HEADERS64
        };
        if (unsafe { (*nt_headers).Signature } != IMAGE_NT_SIGNATURE) {
            Err(anyhow::anyhow!(
                "[x] IMAGE_NT_SIGNATURE '{:?}' invalid (expected {:?}).",
                unsafe { (*nt_headers).Signature },
                IMAGE_NT_SIGNATURE,
            ))?
        }

        Ok(nt_headers)
    }
}
