use core::ffi::c_char;
use std::{arch::asm, os::raw::c_ulong};

use windows::{
    core::PCSTR,
    Win32::{
        Foundation::*,
        System::{
            Diagnostics::Debug::{IMAGE_DATA_DIRECTORY, IMAGE_NT_HEADERS64},
            LibraryLoader::{GetModuleHandleA, GetProcAddress},
            SystemServices::{IMAGE_DOS_HEADER, IMAGE_EXPORT_DIRECTORY},
            Threading::PEB,
            WindowsProgramming::LDR_DATA_TABLE_ENTRY,
        },
    },
};

/// general implementation of the `__readgsqword` C macro.
/// reads from the GS register from a specified offset. uses disassembly from
/// the following C source:
/// ```
/// int main(void) {
///      PTEB pTeb = (PTEB)__readgsqword(0x60);
///      return 0;
/// }
/// ```
///
/// which disassembles to instructions:
/// ```
///   ; ...
///   mov   rax, qword [gs:0x60]
/// ```
///
/// note that this function is specifically for compiling for 64-bit
/// 32-bit compile targets use `__readfsdword(0x30)` (30h offset from `fs`
/// register), and the assembly would be closer to `mov $eax, dword [fs:0x30]`.
#[inline]
#[cfg(target_arch = "x86_64")]
unsafe fn __readgsqword(offset: u64) -> u64 {
    let res: u64;
    asm!(
        "mov {}, qword ptr gs:[{:e}]",
        out(reg) res,
        in(reg) offset,
        options(nostack, preserves_flags)
    );

    return res;
}

fn get_proc_address(h_module: *const HMODULE, t_method: &str) -> FARPROC {
    // cast this here so we don't have to keep recasting
    let p_base = h_module as u64;

    // init header metadata fields
    let p_dos_headers: *const IMAGE_DOS_HEADER;
    let p_nt_headers: *const IMAGE_NT_HEADERS64;
    let p_data_dir: *const IMAGE_DATA_DIRECTORY;
    let p_exp_dir: *const IMAGE_EXPORT_DIRECTORY;

    unsafe {
        // retrieve module exports ptr from module metadata chain
        p_dos_headers = h_module as *const IMAGE_DOS_HEADER;
        p_nt_headers = (p_base + (*p_dos_headers).e_lfanew as u64) as *const IMAGE_NT_HEADERS64;
        p_data_dir =
            (&(*p_nt_headers).OptionalHeader.DataDirectory[0]) as *const IMAGE_DATA_DIRECTORY;
        p_exp_dir = (p_base + (*p_data_dir).VirtualAddress as u64) as *const IMAGE_EXPORT_DIRECTORY;

        // dereference export_directory ptr
        let exp_dir = *p_exp_dir;

        // bind init struct fields
        let p_names = p_base + exp_dir.AddressOfNames as u64;
        let p_funcs = exp_dir.AddressOfFunctions as u64;
        let p_ordinals = p_base + exp_dir.AddressOfNameOrdinals as u64;

        // this could be
        // `for i in 0..exp_dir.NumberOfFunctions - 2 { ...`
        // but i don't really want to change this tbh
        let mut i = 0;

        loop {
            // pointer to array index `i` using the `.add(..` method and dereference to
            // retrieve index val; equiv. to something like:
            // ```
            // pCurrName = (char *)pNames[i];
            // pCurrOrd = (void *)pOrdinals[i];
            // ```
            let p_curr_name = *(p_names as *const c_ulong).add(i as usize);
            let p_curr_ord = *(p_ordinals as *const u16).add(i as usize);

            // create a string value from the dereferenced array index pointer
            let name = std::ffi::CStr::from_ptr((p_base + p_curr_name as u64) as *const c_char)
                .to_str()
                .unwrap();

            if name == t_method {
                // retrieve a ptr to our function's address using the current ordinal ptr
                // as the array index
                let p_curr_addr =
                    ((p_base + p_funcs as u64) as *const u32).add(p_curr_ord as usize);

                println!(
                    "[{}] | ord: {} \t- name: {:?} \t- ptr to fn_addr: {:x?}",
                    i, p_curr_ord, name, p_curr_addr
                );

                // as we retrieved a pointer, we want to dereference that pointer and
                // return it as a `FARPROC`; the `*const u32` probably works fine
                // here, but FARPROC is the correct type and it implements the Option<_>
                // we want to return anyway
                let res: FARPROC =
                    std::mem::transmute(((*p_curr_addr) as u64 + p_base) as *const u32);
                return res as FARPROC;
            }

            // increment index counter if the function name doesnt match the target
            // function name
            i += 1;

            // this might be different for non-`ntdll.dll` modules but it seems like
            // a pointer is misaligned somewhere or something and i dont know why
            if i > exp_dir.NumberOfFunctions - 2 {
                break;
            }
        }

        // function doesn't exist in this module
        return None;
    }
}

unsafe fn get_module_handle(sz_module_name: &str) -> Option<*const HMODULE> {
    let target_module = sz_module_name.to_string().to_lowercase();

    // retrieve PEB pointer via this `__readgsqword` macro recreated from
    // C assembly lmao
    let peb_offset = __readgsqword(0x60);
    let peb = *(peb_offset as *const PEB);

    // cast `LIST_ENTRY` to a pointer to an `LDR_DATA_TABLE_ENTRY`, which contains the
    // `Reserved2` array that we return as a pointer to a module handle
    let mut p_dte = (*peb.Ldr).InMemoryOrderModuleList.Flink as *const LDR_DATA_TABLE_ENTRY;
    let p_mod_head = (*peb.Ldr).InMemoryOrderModuleList;
    let mut p_mod_curr = p_mod_head.Flink;

    // PEB walk to retrieve module base address
    loop {
        let dll_name = (*p_dte)
            .FullDllName
            .Buffer
            .to_string()
            .unwrap()
            .to_lowercase();

        // if the above string slice is eq to the given target module, retrieve the module's
        // base address and cast to a HMODULE const pointer
        if dll_name == target_module {
            let handle = (*p_dte).Reserved2[0];
            return Some(handle as *const HMODULE);
        }

        if p_mod_curr != p_mod_head.Blink {
            p_dte = (*p_mod_curr).Flink as *const LDR_DATA_TABLE_ENTRY;
            p_mod_curr = (*p_mod_curr).Flink;
        } else {
            println!(
                "[-] enumerated all loaded modules - unable to find module '{}'.",
                sz_module_name
            );
            break;
        }
    }

    return None;
}

const T_MODULE: &str = "ntdll.dll";
const T_METHOD: &str = "NtAllocateVirtualMemory";

const W_MODULE: &str = "ntdll.dll\0";
const W_METHOD: &str = "NtAllocateVirtualMemory\0";

fn main() {
    unsafe {
        println!();

        // includes some setup to test our implementation by performing the same
        // calls via the actual windows-rs bindings
        let lp_module: PCSTR = PCSTR::from_raw(W_MODULE.as_ptr());
        let lp_api_name: PCSTR = PCSTR::from_raw(W_METHOD.as_ptr());

        // these are our custom versions of the API functions
        let h_module = get_module_handle(T_MODULE).unwrap();
        let fp_address = get_proc_address(h_module, T_METHOD);

        let api_h_module = GetModuleHandleA(lp_module).unwrap();
        let api_fp_address = GetProcAddress(api_h_module, lp_api_name);

        println!("\n---");
        println!("[+] handle from custom impl: \t\t{:?}", h_module);
        println!("[+] handle from API call: \t\t{:?}", api_h_module.0);
        println!();
        println!(
            "[+] func addr from custom impl: \t{:?}",
            fp_address.unwrap()
        );
        println!(
            "[+] func addr from API call: \t\t{:?}",
            api_fp_address.unwrap()
        );
        println!("---");
    }
}
