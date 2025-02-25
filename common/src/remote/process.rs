use crate::remote::types::SYSTEM_PROCESS_INFORMATION;
use std::ffi::c_void;
use std::ptr::null_mut;
use lazy_static::lazy_static;
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
    pub fn get() -> &'static Vec<SYSTEM_PROCESS_INFORMATION> {
        &PROCESSES.processes
    }

    fn enum_all() -> anyhow::Result<Self> {
        let mut process_information: Vec<SYSTEM_PROCESS_INFORMATION> = Vec::new();

        /* -----------------------------------------------
          * TODO:
          *  replace this with indirect syscall invocation
          *  when the module is implemented :)
          * ----------------------------------------------- */
        let libname = PCSTR("NTDLL.DLL\0".as_ptr() as _);
        let funcname = PCSTR("NtQuerySystemInformation\0".as_ptr() as _);

        let query_system_information: NtQuerySystemInformation = unsafe {
            let proc = GetProcAddress(GetModuleHandleA(libname)?, funcname).unwrap();
            std::mem::transmute(proc)
        };

        let mut alloc_size = 0;
        let mut return_length = 0;

        unsafe {
            let mut _status =
                query_system_information(SystemProcessInformation, null_mut(), 0, &mut alloc_size);

            let mut bytes: Vec<u8> = Vec::with_capacity(alloc_size as usize);
            bytes.set_len(alloc_size as usize);

            _status = query_system_information(
                SystemProcessInformation,
                bytes.as_ptr() as _,
                alloc_size,
                &mut return_length,
            );

            let head_ptr = bytes.as_ptr() as *const SYSTEM_PROCESS_INFORMATION;
            let mut curr_node_ptr = head_ptr;

            loop {
                let mut node = *curr_node_ptr;
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
