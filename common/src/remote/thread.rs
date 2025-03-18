//! Remote thread enumeration tooling

use super::process::Processes;
use anyhow::Result;
use anyhow::anyhow;
use crate::remote::types::SYSTEM_THREAD_INFORMATION;
use alloc::string::{String, ToString};
use libc_print::std_name::println;
use windows::Win32::Foundation::*;

#[repr(C, align(16))]
#[derive(Debug, Copy, Clone)]
pub struct Thread {
    pid: HANDLE,
    tid: HANDLE,
}
impl Thread {
    /// Returns a new `Thread` struct containing a Process's ID (`pid`) and the main thread ID
    /// for that process (`tid`).
    ///
    /// This method invokes `Process::enum_all()` to initialize the static `PROCESSES` variable if
    /// it hasn't already been initialized.
    ///
    /// # PID/TID vs. `HANDLE`
    ///
    /// While the types referenced in `SYSTEM_PROCESS_INFORMATION.UniqueProcessId` and
    /// `SYSTEM_THREAD_INFORMATION.ClientId.UniqueThread` are `HANDLE` types, these are actually
    /// referencing the respective `PID`/`TID` as opposed to a true `HANDLE` type.
    pub fn get_threads(target: &str) -> Result<Self> {
        let process_vec = Processes::get_all();
        for process in process_vec {
            // avoid trying to read `ImageName.Buffer` if the process name is null
            if process.ImageName.Length != 0x00 {
                let name = unsafe { process.ImageName.Buffer.to_string()? };
                if name.to_lowercase() == target.to_lowercase() {
                    return Ok(Self {
                        pid: process.UniqueProcessId,
                        tid: process.Threads.ClientId.UniqueThread,
                    });
                }
            }
        }
        
        Err(anyhow!("No process '{}' found", target))?
    }

    /// Prints some details about a target process's threads to `stdout`:
    ///
    /// * Thread ID
    /// * Start address
    /// * Priority
    /// * State
    ///
    /// Function may panic if a thread's `SYSTEM_THREAD_INFORMATION` struct cannot be dereferenced.
    pub fn list_remote_threads(target_process: &str) -> Result<()> {
        let process_vec = Processes::get_all();

        for process in process_vec {
            let name: String;
            if process.ImageName.Length == 0x00 {
                name = String::from("[[ UNKNOWN_PROCESS_NAME ]]");
            } else {
                name = unsafe { process.ImageName.Buffer.to_string()? };
            }

            if target_process.to_lowercase() != name.to_lowercase() {
                println!("[-] {} (-skipping)", name);
                continue;
            }

            let threads_head_ptr = (&process.Threads) as *const _ as *mut SYSTEM_THREAD_INFORMATION;
            println!(
                "\n[+] Found target '{}' -> enumerating {} threads:",
                name, process.NumberOfThreads
            );
            println!("----------------------------------------------------");

            let thread_count = process.NumberOfThreads as usize;
            for i in 0..thread_count {
                let thread_info = unsafe { *threads_head_ptr.add(i) };
                println!("\t[[ thread {} ]]:", i + 1);
                println!(
                    "\t[{:02?}] Thread ID: {:?}",
                    i + 1,
                    thread_info.ClientId.UniqueThread
                );

                println!(
                    "\t[{:02?}] Thread start address: {:016x?}",
                    i + 1,
                    thread_info.StartAddress
                );

                println!(
                    "\t[{:02?}] Thread priority: {}",
                    i + 1,
                    thread_info.Priority
                );

                println!(
                    "\t[{:02?}] Thread state: {}",
                    i + 1,
                    thread_info.ThreadState
                );

                if i < thread_count - 1 {
                    println!();
                }
            }

            println!("----------------------------------------------------\n");
        }
        println!();
        Ok(())
    }
}
