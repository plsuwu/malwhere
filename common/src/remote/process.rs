//! Remote process enumeration tooling (work in progress)

use crate::hashing::fnv::Fnv;
use crate::remote::types::SYSTEM_PROCESS_INFORMATION;
use crate::syscall::hell::{set_syscall, syscall_4};
use crate::syscall::resolver::{SyscallMap, WinDll};
use alloc::vec;
use alloc::vec::Vec;
use anyhow::anyhow;
use anyhow::Result;
use core::ffi::c_void;
use core::mem::transmute;
use core::ptr::null_mut;
use lazy_static::lazy_static;
use libc_print::libc_println;

// #[allow(non_snake_case)]
// type NtQuerySystemInformation = unsafe extern "system" fn(
//     SystemInformationClass: SYSTEM_INFORMATION_CLASS,
//     SystemInformation: *mut c_void,
//     SystemInformationLength: i32,
//     ReturnLength: *mut i32,
// ) -> i32;

const SYSTEM_PROCESS_INFORMATION_FLAG: i32 = 5;

// todo:
//  probably better OPSEC to just retrieve this each time we need it (rather than keep
//  the snapshot in memory for the lifetime of the application); this means we also drop
//  the reliance on `lazy_static` and reduce our final compiled binary size
lazy_static! {
    pub(crate) static ref PROCESSES: Processes = Processes::enum_all().unwrap();
}

unsafe impl Sync for Processes {}
unsafe impl Send for Processes {}

#[repr(C)]
#[derive(Debug, Clone)]
pub struct Processes {
    pub processes: Vec<SYSTEM_PROCESS_INFORMATION>,
}

impl Processes {
    /// Retrieve a reference to a static vector of `SYSTEM_PROCESS_INFORMATION` structs
    ///
    /// This is Windows' linked list implementation pulled directly from memory and pushed to
    /// Rust's heap-allocated vector.
    pub fn get_all() -> &'static Vec<SYSTEM_PROCESS_INFORMATION> {
        &PROCESSES.processes
    }

    pub fn get(target_proc: &str) -> Result<&SYSTEM_PROCESS_INFORMATION> {
        let processes = Self::get_all();
        for proc in processes.iter() {
            match proc.ImageName.Length > 0 && !proc.ImageName.Buffer.is_null() {
                true => {
                    let name = unsafe { proc.ImageName.Buffer.to_string()? };
                    if &name == target_proc {
                        libc_println!("found process: {}", name);
                        return Ok(proc);
                    }
                }

                _ => continue,
            }
        }

        Err(anyhow!("No process '{}' found", target_proc))?
    }

    /// Retrieves a vector containing a snapshot of all processes running on the system.
    ///
    /// Avoids the `CreateToolhelp32Snapshot` API call by implementing direct syscalls
    fn enum_all() -> Result<Self> {
        let mut process_information: Vec<SYSTEM_PROCESS_INFORMATION> = Vec::new();

        let mut hashes: Vec<u32> = vec![0x6619e14a];
        let mut table = SyscallMap::new(&mut hashes, Fnv, WinDll::Ntdll);

        let mut alloc_size = 0; // determines how much data to read
        let mut return_length = 0; // technically unused but here we are

        unsafe {
            let mut args: [u64; 4] = [
                SYSTEM_PROCESS_INFORMATION_FLAG as u64,
                null_mut::<c_void>() as u64,
                null_mut::<c_void>() as u64,
                transmute(&mut alloc_size),
            ];

            // let s = table.syscalls.get(&hashes[0]).unwrap();
            let s = table.resolve(0)?;

            set_syscall(s.ssn, s.random as u64);
            let mut _status = syscall_4(args.as_ptr());

            // allocate heap space with the size of the linked list
            let mut bytes: Vec<u8> = Vec::with_capacity(alloc_size as usize);
            bytes.fill(0);

            // second query to copy list into allocation
            args = [
                SYSTEM_PROCESS_INFORMATION_FLAG as u64,
                transmute(bytes.as_ptr() as *mut c_void),
                alloc_size as u64,
                transmute(&mut return_length),
            ];

            // println!("args 2: {:016x?}", args);

            set_syscall(s.ssn, s.random as u64);
            _status = syscall_4(args.as_ptr());

            // convert raw bytes to a pointer to the first list item
            let head_ptr = bytes.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;
            let mut curr_node_ptr = head_ptr;

            // traverse list and push each node to a vector
            loop {
                let node = *curr_node_ptr;
                process_information.push(node);

                if node.NextEntryOffset == 0 {
                    break;
                }

                curr_node_ptr = curr_node_ptr.byte_add(node.NextEntryOffset as usize);
            }
        }

        Ok(Self {
            processes: process_information,
        })
    }
}
