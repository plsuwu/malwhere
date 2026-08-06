use core::ffi::c_void;

#[derive(Debug)]
pub struct SyscallEntry {
    pub ssn: u32,
    pub addr: *const c_void,
    pub rand_addr: *const c_void,
}

impl SyscallEntry {
    pub fn retrieve(_hash: u64) -> Option<Self> {
        todo!()
    }
}

#[cfg(test)]
mod test {
    use utilities::obfw;

    use super::*;

    #[test]
    fn resolve_syscall() {
        extern crate std;

        for char in HASH {
            std::print!("\\x{char:04x}");
        }
    }
}
