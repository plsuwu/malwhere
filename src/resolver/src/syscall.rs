extern crate alloc;

use core::ffi::{c_uchar, c_void};
use core::ptr;

use common::prelude::*;
use common::winstring::from_ansi_ptr;

use crate::module::Module;
use crate::unhook::{MAX_JMP_HOPS, OFFSET_RANGE};
use crate::unhook::{check_opcodes, raw_jmp_target, scan_jmp_stub};

#[derive(Debug, Clone, Copy, Default)]
pub struct NtSyscall {
    /// Syscall number
    pub ssn: winapi::DWORD,
    /// Hashed syscall name
    pub name: u64,
    /// Target syscall address
    pub address: winapi::PVOID,
    /// Random address of a syscall instruction
    pub inst_address: winapi::PVOID,
}

impl NtSyscall {
    const NTDLL_NAME_HASH: u64 = widehash!("ntdll.dll\0", &DEFAULT_KEY);

    pub fn new(syscall_name: u64) -> Self {
        let ntcfg = Module::new(Self::NTDLL_NAME_HASH);
        if ntcfg.base.is_null() {
            #[cfg(debug_assertions)]
            eprintln!("module_base is null");

            return Self::default();
        }

        let syscall_addr = Self::walk_module_exports(ntcfg, syscall_name);
        if let Some(ssn) = unsafe { get_ssn(syscall_addr) } {
            return Self {
                ssn,
                name: syscall_name,
                address: syscall_addr as *mut _,
                inst_address: Default::default(),
            };
        }

        Self::default()
    }

    pub fn walk_module_exports(module: Module, syscall_name: u64) -> *const c_void {
        let mut i = 0;
        while i < module.exp_inf.names_len as _ {
            let name_addr: *const c_uchar =
                unsafe { module.base.add(*module.exp_inf.names.add(i) as _) } as _;
            let fn_name = unsafe { from_ansi_ptr(name_addr) };
            if rt_widehash!(&fn_name, &DEFAULT_KEY) == syscall_name {
                let fn_ord = unsafe { *module.exp_inf.ordinals.add(i) };
                let fn_rva = unsafe { *module.exp_inf.funcs.add(fn_ord as _) };
                let fn_addr = unsafe { module.base.add(fn_rva as _) };

                return fn_addr;
            }

            i += 1;
        }

        ptr::null_mut()
    }
}

unsafe fn get_ssn(addr: *const c_void) -> Option<u32> {
    let opcodes = unsafe { core::slice::from_raw_parts(addr as *const u8, 0x08) };

    let maybe_ssn = check_opcodes(opcodes);
    if maybe_ssn.is_some() {
        return maybe_ssn;
    }

    // attempt to follow `E9 rel32` displacement directly to the original stub
    let mut curr = addr;
    for _ in 0..MAX_JMP_HOPS {
        let next = match unsafe { raw_jmp_target(curr) } {
            Some(next) => next,
            None => break,
        };

        #[cfg(debug_assertions)]
        println!("following 0xE9 hook -> {:08x?}", next);

        if let Some(ssn) =
            unsafe { check_opcodes(core::slice::from_raw_parts(next as *const u8, 8)) }
        {
            #[cfg(debug_assertions)]
            return Some(ssn);
        }

        curr = next;
    }

    // fall back to proximity scan (as a best effort) if we find a hook through something
    // other than `E9 rel32` (e.g. indirect `jmp [rip+disp]` trampoline).
    //
    // TODO we realistically should just read in a fresh ntdll.dll at this point as this
    //      has the potential to just be incorrect...
    #[cfg(debug_assertions)]
    println!("0xE9 displacement did not resolve");

    let window = unsafe {
        core::slice::from_raw_parts(
            (addr as *const u8).sub(OFFSET_RANGE - 1),
            OFFSET_RANGE * 2 + 8,
        )
    };

    let maybe_ssn = scan_jmp_stub(window, OFFSET_RANGE - 1);
    if maybe_ssn.is_some() {
        return maybe_ssn;
    }

    None
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::unhook::OFFSET_RANGE;

    /// hooked through a non-`E9` shape (displacement unresolvable) should fall back to the
    /// proximity scan and still finds a stub.
    #[test]
    fn ssn_non_jmp_hook_falls_back_to_scan() {
        let mut window = [0x90u8; OFFSET_RANGE * 2 + 8];
        let addr_off = OFFSET_RANGE - 1;
        let stub_off = addr_off + 0x10;

        // `jmp [rip+disp32]`-style indirect hook/no `E9` displacement
        window[addr_off..addr_off + 6].copy_from_slice(&[0xFF, 0x25, 0x00, 0x00, 0x00, 0x00]);
        window[stub_off..stub_off + 8]
            .copy_from_slice(&[0x4C, 0x8B, 0xD1, 0xB8, 0x55, 0x00, 0x00, 0x00]);

        let ssn = unsafe { get_ssn(window.as_ptr().add(addr_off) as *const c_void) };
        assert_eq!(ssn, Some(0x55));
    }
}
