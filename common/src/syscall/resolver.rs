use crate::environment_block::module::Module;
use crate::hashing::traits::{HashFunction, StringHasher};
use alloc::vec::Vec;
use anyhow::anyhow;
use anyhow::Result;
use core::ffi::c_void;
use core::fmt::Debug;
use core::hash::Hash;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum WinDll {
    Ntdll,
}

/// Details for an arbitrary syscall
#[repr(C)]
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct Syscall {
    /// Syscall number
    pub ssn: u32,
    /// Address of syscall
    pub address: *const c_void,
    /// Random `syscall` instruction in `NTDLL`
    pub random: *const c_void,
}

impl Syscall {
    pub fn zeroed() -> Self {
        unsafe { core::mem::zeroed() }
    }

    /// clear syscall after use
    pub fn clean(&mut self) {
        *self = Self::zeroed();
    }
}

#[repr(C)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyscallMap<T: Hash + Eq + Copy, H: HashFunction<Output = T>> {
    pub hashes: Vec<T>,
    pub hasher: StringHasher<H>,
    dll: WinDll,
    syscall: Syscall,
    index: Option<usize>,
    module: Option<Module>,
}

impl<'a, T: Hash + Eq + Copy + Debug, H: HashFunction<Output = T>> SyscallMap<T, H> {
    pub fn new(hashes: &[T], hash_function: H, dll: WinDll) -> Self
    where
        T: Sized + Copy + Hash + Eq,
    {
        let hasher = StringHasher::new(hash_function);
        let module = Some(Self::init(&dll).unwrap());

        Self {
            hashes: hashes.to_vec(),
            hasher,
            dll,
            syscall: Syscall::zeroed(),
            index: None,
            module,
        }
    }

    pub fn init(dll: &WinDll) -> Result<Module> {
        match dll {
            WinDll::Ntdll => Ok(Module::ntdll()?),
        }
    }

    pub fn resolve(&mut self, index: usize) -> Result<&Syscall>
    where
        <H as HashFunction>::Output: Debug,
    {
        if index >= self.hashes.len() {
            Err(anyhow!("Invalid index '{}'", index))?
        }

        if self.index == Some(index) {
            return Ok(&self.syscall);
        }

        // initialize by zeroing current syscall
        self.syscall.clean();
        self.index = None;

        let module = self.module.as_mut().unwrap();
        let hash = self.hashes[index].clone();
        let mut found = false;

        for idx in 0..module.exports.funcs_count {
            let export_name = module.exports.read_name(idx as isize)?;
            let export_hash = self.hasher.hash(export_name.as_str());

            if export_hash == hash {
                let fn_addr = module.exports.get_function(idx as isize)?;
                let fn_ssn = module.exports.get_ssn(fn_addr);
                let random_syscall = module.exports.get_random(fn_addr)?;

                self.syscall.ssn = fn_ssn;
                self.syscall.address = fn_addr;
                self.syscall.random = random_syscall;

                found = true;
                break;
            }
        }

        if found {
            self.index = Some(index);
            Ok(&self.syscall)
        } else {
            Err(anyhow!("Invalid index '{}'", index))?
        }
    }

    pub fn clean(&mut self) {
        self.syscall.clean();
        self.index = None;
    }
}
