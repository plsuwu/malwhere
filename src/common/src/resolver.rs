#![allow(clippy::missing_safety_doc)]

extern crate alloc;

use alloc::string::String;
use core::ffi::c_void;
use core::ptr;

use crate::hashing::DEFAULT_KEY;
use crate::winapi::PIMAGE_EXPORT_DIRECTORY;
use crate::winstring::{ansi_len, ansi_string_as_slice, from_ansi_ptr, from_wptr, wptr_len};
use crate::{rt_widehash, winapi};

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

#[derive(Debug, Clone, Copy, Default)]
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

impl NtSyscall {
    pub fn new(syscall_name: u64) -> Self {
        let nt_hash = crate::widehash!("ntdll.dll\0", &DEFAULT_KEY);
        let ntcfg = ModuleInfo::new(nt_hash);
        crate::println!("recv result from module: {:?}", ntcfg.module_name);
        if ntcfg.module_base.is_null() {
            crate::println!("module_base is null");
            return Self::default();
        }

        crate::println!("finding VA of names:");

        let names: alloc::vec::Vec<_> = unsafe {
            core::slice::from_raw_parts(
                ntcfg.export_info.addr_of_names,
                ntcfg.export_info.names_len as _,
            )
            .iter()
            .collect()
        };

        let ords: alloc::vec::Vec<_> = unsafe {
            core::slice::from_raw_parts(
                ntcfg.export_info.addr_of_ordinals,
                ntcfg.export_info.names_len as _,
            )
            .iter()
            .collect()
        };

        let funcs: alloc::vec::Vec<_> = unsafe {
            core::slice::from_raw_parts(
                ntcfg.export_info.addr_of_addresses,
                ntcfg.export_info.funcs_len as _,
            )
            .iter()
            .collect()
        };

        assert_eq!(names.len(), ords.len());

        for (i, &&rva) in names.iter().enumerate() {
            let name_addr =
                unsafe { ntcfg.module_base.add(rva as usize) } as *const core::ffi::c_uchar;
            let fn_name = unsafe { from_ansi_ptr(name_addr) };
            if rt_widehash!(&fn_name, &DEFAULT_KEY) == syscall_name {
                let fn_ord = ords[i];
                let fn_addr = unsafe { ntcfg.module_base.add(*funcs[*fn_ord as usize] as usize) };

                crate::println!("'{}' (ord={}) -> {:08x?}", fn_name, i, fn_addr);
            }
        }

        todo!()
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ModuleInfo {
    /// Hashed module name
    pub module_name: u64,
    /// The base address of a module (required for RVA calculation)
    pub module_base: winapi::HANDLE,
    pub export_info: ModuleExportInfo,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ModuleExportInfo {
    /// Number of named functions exported by the module
    pub names_len: winapi::DWORD,
    /// Number of total functions exported by the module
    pub funcs_len: winapi::DWORD,
    /// address of array with names for exported functions
    pub addr_of_names: winapi::PDWORD,
    /// address of array with addresses for exported functions
    pub addr_of_addresses: winapi::PDWORD,
    /// address of array with ordinals for exported functions
    pub addr_of_ordinals: winapi::PWORD,
}

impl ModuleInfo {
    pub fn new(hashed_name: u64) -> Self {
        let peb = unsafe { *(readgsqword(0x60) as *mut winapi::PEB) };

        let p_ldr: *mut winapi::LDR_DATA_TABLE_ENTRY = enumerate_modules(peb, hashed_name);
        if p_ldr.is_null() {
            crate::eprintln!("failed: LDR_DATA_TABLE_ENTRY ptr is null");
            return Self::default();
        }

        let module_base = unsafe { (*p_ldr).DllBase };
        crate::println!("dll_hbase: {:08x?}", module_base);
        if module_base.is_null() {
            crate::eprintln!("failed: module base is null");
            return Self::default();
        }

        crate::println!("validating headers:");

        let p_nt_headers = unsafe { validate_headers(module_base) };
        if p_nt_headers.is_null() {
            crate::eprintln!("failed: headers invalid");
            return Self::default();
        }

        crate::println!("retrieving exports dir:");

        let p_export_directory = unsafe { get_exports_ptr(module_base, *p_nt_headers) };
        if p_export_directory.is_null() {
            return Self::default();
        }

        Self {
            module_base,
            module_name: hashed_name,
            export_info: unsafe { read_exports_info(module_base, p_export_directory) },
        }
    }
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
        crate::eprintln!("failed: resolve export dir: '{:08x?}'", module);
        return core::ptr::null_mut();
    }

    p_img_exp_dir
}

pub unsafe fn read_exports_info(
    module_base: *mut c_void,
    p_export_dir: winapi::PIMAGE_EXPORT_DIRECTORY,
) -> ModuleExportInfo {
    let export_dir = unsafe { *p_export_dir };

    let names_len = export_dir.NumberOfNames;
    let funcs_len = export_dir.NumberOfFunctions;

    let names = unsafe { module_base.add(export_dir.AddressOfNames as _) } as _;
    let addresses = unsafe { module_base.add(export_dir.AddressOfFunctions as _) } as _;
    let ordinals = unsafe { module_base.add(export_dir.AddressOfNameOrdinals as _) } as _;

    ModuleExportInfo {
        names_len,
        funcs_len,
        addr_of_names: names,
        addr_of_addresses: addresses,
        addr_of_ordinals: ordinals,
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
    if target == crate::widehash!("ntdll.dll\0", &DEFAULT_KEY) {
        return ntdll_base(peb);
    }

    let mut curr_list_entry: *mut winapi::LIST_ENTRY =
        unsafe { (*peb.Ldr).InMemoryOrderModuleList.Flink };
    let ldr_head: *mut winapi::LIST_ENTRY = unsafe { (*curr_list_entry).Blink };
    let mut curr: *mut winapi::LDR_DATA_TABLE_ENTRY = curr_list_entry as _;

    loop {
        let full_dll_name = unsafe { (*curr).FullDllName };
        let name = unsafe { from_wptr(full_dll_name.Buffer, full_dll_name.Length) };
        let hash = crate::rt_widehash!(&name, &DEFAULT_KEY);

        crate::println!(
            " -> module: {:24.24} \thash: 0x{:016x?}\taddr: 0x{:016x?}",
            name,
            hash,
            unsafe { (*curr).DllBase }
        );

        if crate::rt_widehash!(&name, &DEFAULT_KEY) == target {
            return curr;
        }

        if curr != unsafe { (*ldr_head).Blink as _ } {
            curr_list_entry = unsafe { (*curr_list_entry).Flink };
            curr = curr_list_entry as _;
        } else {
            break;
        }
    }

    crate::eprintln!("failed to get module: 0x{:016x?}", target);
    ptr::null_mut()
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;
    use crate::hashing::DEFAULT_KEY;

    const NTDLL_NAME_HASH: u64 = crate::widehash!("ntdll.dll\0", &DEFAULT_KEY);
    const JUNKHASH: u64 = crate::widehash!("asdfasdf\0", &DEFAULT_KEY);

    #[test]
    fn module_info_init() {
        let ntdll_info = ModuleInfo::new(JUNKHASH);

        crate::println!(
            "module '0x{:08x?}' @ addr '{:08x?}' ({} exports)",
            ntdll_info.module_name,
            ntdll_info.module_base,
            ntdll_info.export_info.names_len,
        );
    }

    #[test]
    fn ntsyscall_init() {
        let syscall_hash = crate::widehash!("NtSetInformationThread\0", &DEFAULT_KEY);
        let _ntsyscall = NtSyscall::new(syscall_hash);

        todo!()
    }
}
