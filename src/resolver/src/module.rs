use core::{ffi::c_void, ptr};

use crate::readgsqword;
use common::prelude::*;
use common::winapi::PIMAGE_EXPORT_DIRECTORY;
use common::winstring::from_wptr;

#[derive(Debug, Clone, Copy, Default)]
pub struct Module {
    /// Hashed module name
    pub name: u64,
    /// The base address of a module (required for RVA calculation)
    pub base: winapi::HANDLE,
    /// Information on a module's exported functions from its `IMAGE_DIRECTORY_ENTRY_EXPORT`
    pub exp_inf: ModuleExports,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ModuleExports {
    /// Number of named functions exported by the module
    pub names_len: winapi::DWORD,
    /// Number of total functions exported by the module
    pub funcs_len: winapi::DWORD,
    /// address of array with names for exported functions
    pub names: winapi::PDWORD,
    /// address of array with addresses for exported functions
    pub funcs: winapi::PDWORD,
    /// address of array with ordinals for exported functions
    pub ordinals: winapi::PWORD,
}

impl Module {
    pub fn new(hashed_name: u64) -> Self {
        let peb = unsafe { *(readgsqword(0x60) as *mut winapi::PEB) };

        let p_ldr: *mut winapi::LDR_DATA_TABLE_ENTRY = enumerate_modules(peb, hashed_name);
        if p_ldr.is_null() {
            #[cfg(debug_assertions)]
            eprintln!("failed: LDR_DATA_TABLE_ENTRY ptr is null");

            return Self::default();
        }

        let base = unsafe { (*p_ldr).DllBase };
        if base.is_null() {
            #[cfg(debug_assertions)]
            eprintln!("failed: module base is null");

            return Self::default();
        }

        let p_nt_headers = unsafe { validate_headers(base) };
        if p_nt_headers.is_null() {
            #[cfg(debug_assertions)]
            eprintln!("failed: headers invalid");

            return Self::default();
        }

        let p_export_directory = unsafe { get_exports_ptr(base, *p_nt_headers) };
        if p_export_directory.is_null() {
            return Self::default();
        }

        Self {
            base,
            name: hashed_name,
            exp_inf: unsafe { read_exports_info(base, p_export_directory) },
        }
    }
}

pub unsafe fn validate_headers(module: *mut c_void) -> winapi::PIMAGE_NT_HEADERS {
    // check magic `MZ` bytes
    let p_img_dos_hdr: winapi::PIMAGE_DOS_HEADER = module.cast();
    if p_img_dos_hdr.is_null() || unsafe { (*p_img_dos_hdr).e_magic } != winapi::IMAGE_DOS_SIGNATURE
    {
        #[cfg(debug_assertions)]
        eprintln!("IMAGE_DOS_SIGNATURE invalid: {:?}", p_img_dos_hdr);

        return core::ptr::null_mut();
    }

    // check signature in NT headers
    let p_img_nt_hdrs: winapi::PIMAGE_NT_HEADERS =
        unsafe { module.add((*p_img_dos_hdr).e_lfanew as _).cast() };
    if p_img_nt_hdrs.is_null()
        || unsafe { (*p_img_nt_hdrs).Signature } != winapi::IMAGE_NT_SIGNATURE
    {
        #[cfg(debug_assertions)]
        eprintln!("IMAGE_NT_SIGNATURE invalid: {:?}", p_img_nt_hdrs);

        return core::ptr::null_mut();
    }

    p_img_nt_hdrs
}

pub unsafe fn get_exports_ptr(
    module: *mut c_void,
    nt_headers: winapi::IMAGE_NT_HEADERS,
) -> winapi::PIMAGE_EXPORT_DIRECTORY {
    let export_directory_va = (nt_headers.OptionalHeader.DataDirectory
        [winapi::IMAGE_DIRECTORY_ENTRY_EXPORT as usize]
        as winapi::IMAGE_DATA_DIRECTORY)
        .VirtualAddress as usize;

    let p_img_exp_dir: winapi::PIMAGE_EXPORT_DIRECTORY =
        unsafe { module.add(export_directory_va) as PIMAGE_EXPORT_DIRECTORY };

    if p_img_exp_dir.is_null() {
        #[cfg(debug_assertions)]
        eprintln!("failed: resolve export dir: '{:08x?}'", module);

        return core::ptr::null_mut();
    }

    p_img_exp_dir
}

pub unsafe fn read_exports_info(
    base: *mut c_void,
    p_export_dir: winapi::PIMAGE_EXPORT_DIRECTORY,
) -> ModuleExports {
    let export_dir = unsafe { *p_export_dir };

    let names_len = export_dir.NumberOfNames;
    let funcs_len = export_dir.NumberOfFunctions;

    let names = unsafe { base.add(export_dir.AddressOfNames as _) } as _;
    let funcs = unsafe { base.add(export_dir.AddressOfFunctions as _) } as _;
    let ordinals = unsafe { base.add(export_dir.AddressOfNameOrdinals as _) } as _;

    ModuleExports {
        names,
        funcs,
        ordinals,
        names_len,
        funcs_len,
    }
}

fn ntdll_base(peb: winapi::PEB) -> *mut winapi::LDR_DATA_TABLE_ENTRY {
    unsafe {
        (*(*peb.Ldr).InMemoryOrderModuleList.Flink)
            .Flink
            .byte_sub(0x10) as _
    }
}

fn enumerate_modules(peb: winapi::PEB, target: u64) -> *mut winapi::LDR_DATA_TABLE_ENTRY {
    if target == widehash!("ntdll.dll\0", &DEFAULT_KEY) {
        return ntdll_base(peb);
    }

    let mut curr_list_entry: *mut winapi::LIST_ENTRY =
        unsafe { (*peb.Ldr).InMemoryOrderModuleList.Flink };
    let ldr_head: *mut winapi::LIST_ENTRY = unsafe { (*curr_list_entry).Blink };
    let mut curr: *mut winapi::LDR_DATA_TABLE_ENTRY = curr_list_entry as _;

    loop {
        let full_dll_name = unsafe { (*curr).FullDllName };
        let name = unsafe { from_wptr(full_dll_name.Buffer, full_dll_name.Length) };
        let hash = common::rt_widehash!(&name, &DEFAULT_KEY);

        #[cfg(debug_assertions)]
        println!(
            " -> module: {:24.24} \thash: 0x{:016x?}\taddr: 0x{:016x?}",
            name,
            hash,
            unsafe { (*curr).DllBase }
        );

        if common::rt_widehash!(&name, &DEFAULT_KEY) == target {
            return curr;
        }

        if curr != unsafe { (*ldr_head).Blink as _ } {
            curr_list_entry = unsafe { (*curr_list_entry).Flink };
            curr = curr_list_entry as _;
        } else {
            break;
        }
    }

    #[cfg(debug_assertions)]
    eprintln!("failed to get module: 0x{:016x?}", target);

    ptr::null_mut()
}
