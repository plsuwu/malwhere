use anyhow::Result;
use common::environment_block::fetcher::Module;
use common::hashing::traits::{HashFunction, StringHasher};
use std::collections::HashMap;
use std::fmt::Debug;
use std::hash::Hash;

/// Details for an arbitrary syscall
#[repr(C)]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Syscall {
    /// Syscall number
    pub ssn: u32,
    /// Address of syscall
    pub address: *const std::ffi::c_void,
    /// Random `syscall` instruction in `NTDLL`
    pub random: *const std::ffi::c_void,
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallMap<T: Hash + Eq, H: HashFunction> {
    pub syscalls: HashMap<T, Syscall>,
    pub hasher: StringHasher<H>,
}

impl<T: Hash + Eq, H: HashFunction<Output = T>> SyscallMap<T, H> {
    pub fn new(hashed_calls: &mut [T], hash_function: H) -> Self
    where
        T: Sized + Copy + Hash + Eq,
    {
        let mut syscalls = HashMap::new();
        hashed_calls.iter().for_each(|&h| {
            let syscall_empty: Syscall = unsafe { std::mem::zeroed() };
            syscalls.insert(h, syscall_empty);
        });

        let hasher = StringHasher::new(hash_function);

        Self { syscalls, hasher }
    }

    pub fn resolve(&mut self) -> Result<()>
    where
        <H as HashFunction>::Output: Debug,
    {
        let ntdll = Module::ntdll()?;

        for index in 0..ntdll.exports.funcs_count {
            let export_name = ntdll.exports.read_name(ntdll.module_base, index as isize)?;

            let export_name_hash = self.hasher.hash(export_name.as_str());
            if let Some(syscall) = self.syscalls.get_mut(&export_name_hash) {
                let fn_addr = ntdll
                    .exports
                    .get_function(ntdll.module_base, index as isize)?;
                let fn_ssn = ntdll.exports.get_ssn(fn_addr)?;

                syscall.ssn = fn_ssn;
                syscall.address = fn_addr;

                // TODO: implement fetching address of a random syscall

            }
        }

        Ok(())
    }
}
