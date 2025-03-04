//! Fetching and parsing of `.dll` modules.
//!
//! Currently only implements fetching `ntdll.dll` via an offset from the module's
//! `LoaderData` field.
//!
//! TODO:
//!     needs refactoring out to split between syscall vs. module retrieval

use crate::environment_block::read_gs::GetBlock;
use crate::environment_block::types::{
    LDR_DATA_TABLE_ENTRY, PEB_LDR_DATA, PROCESS_ENVIRONMENT_BLOCK,
};
use lazy_static::lazy_static;
use rand::random_range;
use std::ffi::{c_void, CStr};
use windows::Win32::System::Diagnostics::Debug::IMAGE_NT_HEADERS64;
use windows::Win32::System::SystemServices::{
    IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
};

pub const IMAGE_DIRECTORY_ENTRY_EXPORT: usize = 0;
const SYSCALL_OPCODES: [u8; 6] = [0x4c, 0x8b, 0xd1, 0xb8, 0x00, 0x00];
const SYSCALL_INSTRUCTION: [u8; 2] = [0x0f, 0x05];

const JMP_OPCODE: u8 = 0xe9;
const DOWN: isize = 32;
const UP: isize = -32;

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
    pub module_base: *mut c_void,
    pub export_directory: *mut IMAGE_EXPORT_DIRECTORY,
    pub syscall_index_bounds: Option<(isize, isize)>,
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
            module_base,
            export_directory: export_addr,
            syscall_index_bounds: None,
        })
    }

    pub fn read_name(&self, index: isize) -> anyhow::Result<String> {
        let rva = unsafe { *self.names_array.offset(index) };
        let name = unsafe {
            CStr::from_ptr(self.module_base.byte_offset(rva as isize) as *mut i8).to_str()?
        };

        Ok(name.to_string())
    }

    pub fn get_function(&self, index: isize) -> anyhow::Result<*mut c_void> {
        let ord_index = unsafe { *self.ordls_array.offset(index) };
        let fn_rva = unsafe { *self.addrs_array.offset(ord_index as isize) };
        let fn_address = unsafe { self.module_base.byte_add(fn_rva as usize) };

        Ok(fn_address)
    }

    // this would be more efficient as a binary search but it just gets
    // increasingly complex
    pub fn syscall_subset(&mut self) -> anyhow::Result<()> {
        let mut lower: isize = -1;
        let mut upper: isize = -1;
        for i in 0..self.names_count as isize {
            let curr = self
                .get_curr(i as usize)
                .starts_with("Nt");
            if curr && lower == -1 {
                lower = i;
            }

            if !curr && lower > -1 {
                upper = i;
                break;
            }
        }

        self.syscall_index_bounds = Some((lower, upper));
        Ok(())
    }

    fn get_curr(&self, mid: usize) -> String {
        String::from_iter(
            self.read_name(mid as isize)
                .unwrap()
                .chars()
                .take(2)
                .collect::<Vec<_>>(),
        )
    }

    pub fn get_random(&mut self, _addr: *const c_void) -> anyhow::Result<*mut c_void> {
        if self.syscall_index_bounds.is_none() {
            self.syscall_subset()?;
        }
        let rand_index = {
            let range_size =
                self.syscall_index_bounds.unwrap().1 - self.syscall_index_bounds.unwrap().0;
            let index_offset = random_range(0..range_size as usize);
            self.syscall_index_bounds.unwrap().0 as usize + index_offset
        };

        // let name = self.read_name(rand_index as isize)?;
        let addr = self.get_function(rand_index as isize)? as *const u8;

        // let rand_addr = unsafe { addr.offset(0xff) } as *mut u8;

        for &dir in &[1, -1] {
            for idx in 0..=0xff {
                let bytes = unsafe {
                    let offset = addr.byte_offset(idx * dir);
                    [*offset, *offset.byte_add(1)]
                };

                if bytes == SYSCALL_INSTRUCTION {
                    unsafe { return Ok(addr.byte_offset(idx * dir) as *mut c_void ) }
                }
            }
        }

        Err(anyhow::anyhow!(
            "[x] Could not find syscall near 0xff + syscall_address: '{:?}'.",
            addr
        ))
        //     name
        // ))
    }

    pub fn get_ssn(&self, address: *mut c_void) -> u32 {
        let hi = unsafe { *((address as u64 + 5) as *const u8) };
        let lo = unsafe { *((address as u64 + 4) as *const u8) };

        (hi.wrapping_shl(8) | lo) as u32
    }

    // TODO: implement testing for this with patched hooking
    pub fn check_neighbor(&self, address: *mut c_void) -> anyhow::Result<u32> {
        let directions = &[DOWN, UP];
        for &dir in directions {
            for idx in 1..0xff {
                let neighbor = unsafe { address.byte_offset(idx * dir) };
                if let Some(ssn) = self.match_bytes(neighbor) {
                    return Ok(ssn);
                }
            }
        }

        Err(anyhow::anyhow!(
            "[x] Unable to validate function opcodes in neighboring bytes."
        ))
    }

    pub fn match_bytes(&self, address: *mut c_void) -> Option<u32> {
        unsafe {
            let ptr = address as *const u8;
            let fn_bytes = [
                *ptr,
                *ptr.add(1),
                *ptr.add(2),
                *ptr.add(3),
                *ptr.add(6),
                *ptr.add(7),
            ];

            if fn_bytes == SYSCALL_OPCODES {
                return Some(self.get_ssn(address));
            }
        }

        None
    }

    pub fn verify_bytes(&self, address: *mut c_void) -> anyhow::Result<u32> {
        if let Some(ssn) = self.match_bytes(address) {
            return Ok(ssn);
        }

        unsafe {
            let ptr = address as *const u8;
            if *ptr == JMP_OPCODE || *ptr.add(2) == JMP_OPCODE {
                return self.check_neighbor(address);
            }
        }

        Err(anyhow::anyhow!("[x] Couldn't validate SSN."))
    }
}

#[repr(C)]
#[derive(Debug)]
pub struct Module {
    pub module_name: String,
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

        let module_name = unsafe { (*loader_entry).BaseDllName.Buffer.to_string()? };
        let module_base = unsafe { (*loader_entry).DllBase };

        // confirm our location and carve out function export directory
        let nt_headers = Self::get_headers(module_base as _)?;
        let export_addr = Self::get_exports(module_base as _, nt_headers)?;

        let exports = ModuleExports::new(module_base, export_addr)?;
        Ok(Self {
            module_name,
            module_base,
            exports,
        })
    }

    /// Resolves the address of the module's `IMAGE_EXPORT_DIRECTORY` using the
    /// `IMAGE_NT_HEADERS.OptionalHeader.DataDirectory[0]` RVA to offset the module's base
    /// address
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

    /// Retrieves NT headers of a PE file;
    ///
    /// Also verifies DOS + NT header signatures to confirm we are where we expect to
    /// be in the module
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
