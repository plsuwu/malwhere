//! Remote process enumeration tooling (work in progress)

use crate::remote::types::SYSTEM_PROCESS_INFORMATION;
use lazy_static::lazy_static;
use std::ffi::c_void;
use std::ptr::null_mut;
use windows::core::PCSTR;
use windows::Wdk::System::SystemInformation::{SystemProcessInformation, SYSTEM_INFORMATION_CLASS};
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
#[allow(non_snake_case)]
type NtQuerySystemInformation = unsafe extern "system" fn(
    SystemInformationClass: SYSTEM_INFORMATION_CLASS,
    SystemInformation: *mut c_void,
    SystemInformationLength: i32,
    ReturnLength: *mut i32,
) -> i32;

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

        /* ---------------------------------------------------------------------------------
         * TODO:
         *  replace this with indirect syscall invocation when the module is implemented :)
         * --------------------------------------------------------------------------------- */
        let libname = PCSTR("NTDLL.DLL\0".as_ptr() as _);
        let funcname = PCSTR("NtQuerySystemInformation\0".as_ptr() as _);

        let query_system_information: NtQuerySystemInformation = unsafe {
            let proc = GetProcAddress(GetModuleHandleA(libname)?, funcname).unwrap();
            std::mem::transmute(proc)
        };

        let mut alloc_size = 0;         // determines how much data to read
        let mut return_length = 0;      // technically unused but here we are

        unsafe {
            // initial query to fetch size of all `SYSTEM_PROCESS_INFORMATION` structs in memory
            //
            // i don't know if Rust will resize my allocation automatically or if Windows will just
            // eat shit and `STATUS_ACCESS_VIOLATION` me + i cant be bothered finding out rn
            let mut _status = query_system_information(
                SystemProcessInformation,   // replace w/ `5i32`
                null_mut(),
                0,
                &mut alloc_size
            );

            // allocate heap space with the size of the linked list
            let mut bytes: Vec<u8> = Vec::with_capacity(alloc_size as usize);
            bytes.fill(0);

            // second query to copy list into allocation
            _status = query_system_information(
                SystemProcessInformation,
                bytes.as_ptr() as _,
                alloc_size,
                &mut return_length,
            );

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
