#![allow(clippy::missing_safety_doc)]

use core::ffi::c_void;

use crate::winapi;
use crate::winapi::PIMAGE_EXPORT_DIRECTORY;

// TODO replace this with something that doesn't look so obviously like PEB pointer retrieval
//      -> see e.g. https://synawk.com/blog/peb-obfuscation-malware-dev-0x4
#[inline]
#[cfg(all(target_pointer_width = "64", target_arch = "x86_64"))]
pub unsafe fn readgsqword(offset: u64) -> u64 {
    let res;
    unsafe {
        core::arch::asm!(
            "mov {}, qword ptr gs:[{:e}]",
            out(reg) res,
            in(reg) offset,
            options(nostack, pure, readonly, preserves_flags)
        );
    }
    res
}

// const MIN_OFFSET_RANGE: usize = 0xBED;

pub struct NtSyscall {
    /// Syscall number
    pub ssn: winapi::DWORD,
    /// Hashed syscall name
    pub syscall_name: u64,
    /// Target syscall address
    pub syscall_addr: winapi::PVOID,
    /// Random address of a syscall instruction
    pub syscall_inst_addr: winapi::PVOID,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ModuleInfo {
    /// Hashed module name
    pub module_name: u64,
    /// The base address of a module (required for RVA calculation)
    pub module_base: winapi::ULONG_PTR,
    pub export_info: ModuleExportInfo,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ModuleExportInfo {
    /// Number of named functions exported by the module
    pub names_len: winapi::DWORD,
    /// address of array with names for exported functions
    pub addr_of_names: winapi::PDWORD,
    /// address of array with addresses for exported functions
    pub addr_of_addresses: winapi::PDWORD,
    /// address of array with ordinals for exported functions
    pub addr_of_ordinals: winapi::PWORD,
}

pub unsafe fn validate_headers(module: *mut c_void) -> winapi::PIMAGE_NT_HEADERS {
    // check magic `MZ` bytes
    let p_img_dos_hdr: winapi::PIMAGE_DOS_HEADER = module.cast();
    if p_img_dos_hdr.is_null() || unsafe { (*p_img_dos_hdr).e_magic } != winapi::IMAGE_DOS_SIGNATURE
    {
        crate::eprintln!("p_image_dos_hdr invalid: {:?}", p_img_dos_hdr);
        return core::ptr::null_mut();
    }

    // check signature in NT headers
    let p_img_nt_hdrs: winapi::PIMAGE_NT_HEADERS =
        unsafe { module.add((*p_img_dos_hdr).e_lfanew as _).cast() };
    if p_img_nt_hdrs.is_null()
        || unsafe { (*p_img_nt_hdrs).Signature } != winapi::IMAGE_NT_SIGNATURE
    {
        crate::eprintln!("p_img_nt_hdrs invalid: {:?}", p_img_nt_hdrs);
        return core::ptr::null_mut();
    }

    p_img_nt_hdrs
}

pub unsafe fn fetch_export_dir(
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
        crate::eprintln!("failed: resolve export dir: '{:08x?}'", module);
        return core::ptr::null_mut();
    }

    p_img_exp_dir
}

/// Returns `(number_of_names, names_addr, addresses_addr, ordinals_addr)`.
pub unsafe fn resolve_export_info(
    module_base: *mut c_void,
    p_export_dir: winapi::PIMAGE_EXPORT_DIRECTORY,
) -> ModuleExportInfo {
    let export_dir = unsafe { *p_export_dir };

    let names_len = export_dir.NumberOfNames;
    let names = unsafe { module_base.add(export_dir.AddressOfNames as _) } as _;
    let addresses = unsafe { module_base.add(export_dir.AddressOfFunctions as _) } as _;
    let ordinals = unsafe { module_base.add(export_dir.AddressOfNameOrdinals as _) } as _;

    ModuleExportInfo {
        names_len,
        addr_of_names: names,
        addr_of_addresses: addresses,
        addr_of_ordinals: ordinals,
    }
}

impl ModuleInfo {
    pub fn new(hashed_name: u64) -> Self {
        let peb = unsafe { *(readgsqword(0x60) as *mut winapi::PEB) };

        // TODO: this only directly resolves NTDLL atm, so `hashed_name` is kind of meaningless...
        let p_ldr: *mut winapi::LDR_DATA_TABLE_ENTRY = unsafe {
            (*(*peb.Ldr).InMemoryOrderModuleList.Flink)
                .Flink
                .byte_sub(0x10)
        } as _;

        let module_base = unsafe { (*p_ldr).DllBase };
        if module_base.is_null() {
            crate::eprintln!("failed: resolve module '{:08x?}'", hashed_name);
            return Self::default();
        }

        let p_nt_headers = unsafe { validate_headers(module_base) };
        if p_nt_headers.is_null() {
            return Self::default();
        }

        let p_export_directory = unsafe { fetch_export_dir(module_base, *p_nt_headers) };
        if p_export_directory.is_null() {
            return Self::default();
        }

        Self {
            module_name: hashed_name,
            module_base: module_base as _,
            export_info: unsafe { resolve_export_info(module_base, p_export_directory) },
        }
    }
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use crate::hashing::DEFAULT_KEY;

    const NTDLL_NAME_HASH: u64 = crate::widehash!("ntdll.dll", &DEFAULT_KEY);

    #[test]
    fn module_info_init() {
        let ntdll_info = ModuleInfo::new(NTDLL_NAME_HASH);

        crate::println!(
            "module '0x{:08x?}' @ addr '{:08x?}' ({} exports)",
            ntdll_info.module_name,
            ntdll_info.module_base,
            ntdll_info.export_info.names_len,
        );
    }
}
