use std::arch::asm;
use windows::Win32::{
    Foundation::HMODULE,
    System::{Threading::PEB, WindowsProgramming::LDR_DATA_TABLE_ENTRY},
};

// (naive) implementation of the C/C++ macro `__readgsqword`; intended for x64-based ISA targets as
// x86 systems use a different register and offset (`dword`` from the `fs` register at an offset
//  of `0x30`). based on a dissassembled call to the C/C++ macro to read a pointer offset
// to the PEB:
// ```
//  ; PPEB pPeb = (PPEB)__readgsqword(0x60);
//  mov rax, qword [gs:0x60]
// ```
#[inline]
#[cfg(target_arch = "x86_64")]
pub unsafe fn __readgsqword(offset: u64) -> u64 {
    let mut out: u64;
    asm!(
        "mov {}, gs:[{}]",
        out(reg) out,
        in(reg) offset,
        options(nostack, preserves_flags, readonly)
    );

    return out;
}

pub trait New {
    unsafe fn new() -> Self;
    unsafe fn get_module(self, module_name: &str) -> Option<u64>;
}

impl New for PEB {
    unsafe fn new() -> Self {
        let peb_offset = __readgsqword(0x60);
        let peb = *(peb_offset as *const PEB);

        return peb as PEB;
    }

    // PEB walk to retrieve the base address of a given module; i don't think we use this as we only
    // need `ntdll.dll` given the syscall focus of it all, but this is here as a trait method for 
    // `windows-rs`'s PEB struct and i built it so its here now
    unsafe fn get_module(self, module_name: &str) -> Option<u64> {
        let module_name = module_name.to_lowercase();

        let p_ldr = self.Ldr;
        let p_mod_head = (*p_ldr).InMemoryOrderModuleList;

        let mut p_data_table_entry =
            (*p_ldr).InMemoryOrderModuleList.Flink as *const LDR_DATA_TABLE_ENTRY;
        let mut p_mod_curr = p_mod_head.Flink;

        // PEB walk 
        loop {
            let dll_name = (*p_data_table_entry)
                .FullDllName
                .Buffer
                .to_string()
                .unwrap()
                .to_lowercase();
            
            // if current node's DLL name matches the target module name, we return a handle
            // to this module - note we don't care about the other details this struct will contain,
            // so we cast the handle as a flat `u64` prior to returning.
            if dll_name == module_name {
                let h_module = (*p_data_table_entry).Reserved2[0];
                return Some(h_module as *const HMODULE as u64);
            }

            // otherwise, if the current node is not the last node and is not the 
            // target module, we increment the counter and continue;
            // finally, if we're on the final node and it is not the target module,
            // report that the module wasn't found and break to return a `None` value
            if p_mod_curr != p_mod_head.Blink {
                p_data_table_entry = (*p_mod_curr).Flink as *const LDR_DATA_TABLE_ENTRY;
                p_mod_curr = (*p_mod_curr).Flink;
            } else {
                println!("[x] unable to find '{}' in loaded modules.", module_name);
                break;
            }
        }

        return None;
    }
}

// discluding this because i would need to create an impl for the trait function
// `get_module` and i dont really see the point of that lmao

// impl New for TEB {
//     unsafe fn new() -> Self {
//         let teb_offset = __readgsqword(0x30);
//         let teb = *(teb_offset as *const TEB);

//         return teb as TEB;
//     }
// }
