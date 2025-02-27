use lazy_static::lazy_static;
use std::collections::HashSet;
use std::hash::Hash;
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

#[derive(Debug)]
pub struct SyscallRegistry<T> {
    targets: HashSet<T>,
    syscalls: Vec<ResolvedSyscall<T>>,
}

/// Holds details of a given syscall
#[derive(Debug)]
pub struct ResolvedSyscall<T> {
    /// Syscall number
    ssn: u32,
    /// Hashed syscall name
    hash: T,
    /// Address of syscall
    address: *const std::ffi::c_void,
    /// Random `syscall` instruction in `NTDLL`
    rand_instruct_address: *const std::ffi::c_void,
}

impl<T> SyscallRegistry<T> {
    pub fn new(hashed_calls: &mut [T]) -> Self
    where
        T: Sized + Copy + Hash + Eq,
    {
        let mut hs = HashSet::new();
        hashed_calls.iter().for_each(|&h| {
            hs.insert(h);
        });

        Self {
            targets: hs,
            syscalls: Vec::<ResolvedSyscall<T>>::new(),
        }
    }
}
