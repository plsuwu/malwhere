#![allow(clippy::missing_safety_doc)]

extern crate alloc;

use core::ffi::c_void;
use core::ptr;

use crate::hashing::DEFAULT_KEY;
use crate::winapi;
use crate::winapi::PIMAGE_EXPORT_DIRECTORY;
use crate::winstring::{ansi_len, from_wptr, wptr_len};

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
        let nt_hash = crate::widehash!("ntdllaskdjhf.dll\0", &DEFAULT_KEY);
        let ntcfg = ModuleInfo::new(nt_hash);
        crate::println!("recv result from module: {:?}", ntcfg.module_name);
        if ntcfg.module_base.is_null() {
            crate::println!("module_base is null");
            return Self::default();
        }

        crate::println!("finding VA of names:");

        let names: alloc::vec::Vec<_> = unsafe {
            core::slice::from_raw_parts(
                ntcfg.export_info.addr_of_names.addr() as *mut u32,
                ntcfg.export_info.names_len as _,
            )
            .iter()
            .collect()
        };

        crate::println!("{:#08x?}", names);

        let rva_10 = names[10];
        let addr = unsafe { ntcfg.module_base.add(*rva_10 as usize) } as *const core::ffi::c_char;

        crate::println!("n: {:08x?}", addr);

        // let strlen = unsafe { ansi_len(addr) };

        // for &rva in names {
        //
        //     // alloc::string::String::from_utf8_lossy
        //
        // }

        // i += 1;

        //     let array_offset = i * size_of::<u32>();
        //     let p_fn_name: *mut u8 =
        //         { unsafe { ntcfg.export_info.addr_of_names.add(array_offset).addr() } } as _;
        //
        //     crate::println!("pfn_name: {:08x?}", p_fn_name);
        //     // let p_fn_addr =
        //     //     ntcfg.module_base + unsafe { ntcfg.export_info.addr_of_addresses.add(i).addr() };
        //
        //     let fn_name_len: usize = {
        //         let mut len = 0;
        //         while unsafe { *p_fn_name.add(len) } != 0 && len < 260 {
        //             len += 1;
        //         }
        //
        //         len as _
        //     };
        //
        //     let fn_name_res = unsafe {
        //         extern crate alloc;
        //
        //         let sl = core::slice::from_raw_parts(p_fn_name, fn_name_len);
        //         alloc::string::String::from_utf8_lossy(sl)
        //     };
        //     //
        //     crate::println!("p_fn_name: {}", fn_name_res);
        //     // crate::println!("p_fn_addr: 0x{:016x?}", p_fn_addr);
        //
        //     i += 1;
        // }

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
    let mut curr_list_entry: *mut winapi::LIST_ENTRY =
        unsafe { (*peb.Ldr).InMemoryOrderModuleList.Flink };
    let ldr_head: *mut winapi::LIST_ENTRY = unsafe { (*curr_list_entry).Blink };
    let mut curr: *mut winapi::LDR_DATA_TABLE_ENTRY = curr_list_entry as _;

    loop {
        let full_dll_name = unsafe { (*curr).FullDllName };
        let name = unsafe { from_wptr(full_dll_name.Buffer, full_dll_name.Length) };
        let hash = crate::rt_widehash!(&name, &DEFAULT_KEY);

        crate::println!(" -> module: {:24.24} \thash: 0x{:016x?}\taddr: 0x{:016x?}", name, hash, 
            unsafe { (*curr).DllBase });

        if crate::rt_widehash!(&name, &DEFAULT_KEY) == target {
            crate::println!("found target ok: base @ {:08x?}", unsafe {
                (*curr).DllBase
            });
            crate::println!("from manual res: {:08x?}", ntdll_base(peb));
            // return curr;
        }

        if curr != unsafe { (*ldr_head).Blink as _ } {
            curr_list_entry = unsafe { (*curr_list_entry).Flink };
            curr = curr_list_entry as _;
        } else {
            break;
        }
    }

    if target == crate::widehash!("ntdll.dll\0", &DEFAULT_KEY) {
        return ntdll_base(peb);
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
    const JUNKHASH: u64 =  crate::widehash!("asdfasdf\0", &DEFAULT_KEY);

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
