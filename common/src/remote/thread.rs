use super::process::Processes;
use crate::remote::types::SYSTEM_THREAD_INFORMATION;
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
    pub fn get_threads(target: &str) -> anyhow::Result<Self> {
        // retrieve a reference to the `SYSTEM_PROCESS_INFORMATION` vector
        let process_vec = Processes::get();

        // enumerate through the vector to retrieve
        for process in process_vec {
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

        Err(anyhow::anyhow!("[x] No process '{}'.", target))
    }

    pub fn list_remote_threads(target_process: &str) -> anyhow::Result<()> {
        let process_vec = Processes::get();

        for process in process_vec {
            let mut name: String;
            if process.ImageName.Length == 0x00 {
                name = String::from("[[ UNKNOWN_PROCESS_NAME ]]");
            } else {
                name = unsafe { process.ImageName.Buffer.to_string()? };
            }

            if target_process.to_lowercase() != name.to_lowercase() {
                println!("[-] {} (-skipping)", name);
                continue;
            }

            let mut threads_head_ptr =
                (&process.Threads) as *const _ as *mut SYSTEM_THREAD_INFORMATION;
            println!(
                "[+] Got target -> enumerating {} threads:",
                process.NumberOfThreads
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

                println!();
            }

            println!("----------------------------------------------------");
        }

        Ok(())
    }
}
