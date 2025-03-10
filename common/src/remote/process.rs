//! Remote process enumeration tooling (work in progress)

use crate::hashing::fnv::Fnv;
use crate::remote::types::SYSTEM_PROCESS_INFORMATION;
use crate::syscall::hell::{set_syscall, syscall_4};
use crate::syscall::resolver::SyscallMap;
use lazy_static::lazy_static;
use std::ffi::c_void;
use std::mem::transmute;
use std::ptr::null_mut;
use windows::Wdk::System::SystemInformation::SYSTEM_INFORMATION_CLASS;

#[allow(non_snake_case)]
type NtQuerySystemInformation = unsafe extern "system" fn(
    SystemInformationClass: SYSTEM_INFORMATION_CLASS,
    SystemInformation: *mut c_void,
    SystemInformationLength: i32,
    ReturnLength: *mut i32,
) -> i32;

const SYSTEM_PROCESS_INFORMATION_FLAG: i32 = 5;

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
    pub fn get() -> &'static Vec<SYSTEM_PROCESS_INFORMATION> {
        &PROCESSES.processes
    }

    /// Retrieves a vector containing a snapshot of all processes running on the system.
    ///
    /// Avoids the `CreateToolhelp32Snapshot` API call by implementing direct syscalls
    /// (current impl invokes `GetProcAddress` + `GetModuleHandle` so it is what it is for now)
    fn enum_all() -> anyhow::Result<Self> {
        let mut process_information: Vec<SYSTEM_PROCESS_INFORMATION> = Vec::new();


        let mut hashes: Vec<u32> = vec![0x6619e14a];
        let mut table = SyscallMap::new(&mut hashes, Fnv);

        table.resolve()?;

        println!("RESOLVED SYSCALL TABLE: {:#016x?}", table);

        let mut alloc_size = 0;         // determines how much data to read
        let mut return_length = 0;      // technically unused but here we are

        unsafe {

            let mut args: [u64; 4] = [
                SYSTEM_PROCESS_INFORMATION_FLAG as u64,
                null_mut::<c_void>() as u64,
                null_mut::<c_void>() as u64,
                transmute(&mut alloc_size),
            ];

            let s = table.syscalls.get(&hashes[0]).unwrap();
            set_syscall(s.ssn, s.random as u64);

            let mut _status = syscall_4(args.as_ptr());

            // println!("NTSTATUS: {:#016x?}", _status);
            // println!("ALLOC: {:#016x?}", alloc_size);

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

            println!("args 2: {:016x?}", args);

            _status = syscall_4(args.as_ptr());

            // convert raw bytes to a pointer to the first list item
            let head_ptr =
                bytes.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;
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
