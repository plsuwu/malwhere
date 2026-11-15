#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

extern crate alloc;

use core::ffi::{c_uchar, c_void};
use core::ptr;
use core::slice::from_raw_parts;

use common::prelude::*;
use common::winapi::{HANDLE, PVOID, SIZE_T, ULONG, ULONG_PTR};
use common::winstring::from_ansi_ptr;

use crate::module::Module;
use crate::unhook::OFFSET_RANGE;
use crate::unhook::{check_opcodes, raw_jmp_target, scan_jmp_stub};

pub const MAX_JMP_HOPS: usize = 4;

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

/// Indirect syscall that uses the stack to pass arguments (6-arg call).
///
/// NOTE: Windows syscalls don't behave as expected through Wine as they are often translated to a
/// Linux equivalent "under the hood", completely bypassing the Windows syscall (which makes sense
/// in hindsight). Trying to call `NtAllocateVirtualMemory` this way will not work correctly on 
/// Wine - which is kind of good to know, in all reality.
///
/// TODO: perhaps attempt to make this more generic - base on arg count rather than being specific
/// to `NtAllocateVirtualMemory`...
pub unsafe fn _NtAllocateVirtualMemory(
    syscall: &NtSyscall,
    ProcessHandle: HANDLE,
    BaseAddress: *mut PVOID,
    ZeroBits: ULONG_PTR,
    RegionSize: *mut SIZE_T,
    AllocationType: ULONG,
    Protect: ULONG,
) -> i32 {
    let mut status: u64;
    unsafe {
        core::arch::asm!(
            // the syscall stub reads the stack at `[rsp+0x28]` and `[rsp+0x30]` after `call`
            // pushes the return address
            "push rbp",
            "push {protect}",
            "push {alloc_type}",
            "sub rsp, 0x20",        // shadow space
            "call {inst}",          // `inst` is a ptr to `0x0f,0x05`
            "add rsp, 0x30",
            "pop rbp",
            inst = in(reg) syscall.inst_address,
            // `rax` is SSN on input and `NTSTATUS` on output
            inout("rax") syscall.ssn as u64 => status,
            in("r10") ProcessHandle as u64,
            in("rdx") BaseAddress as u64,
            in("r8") ZeroBits as u64,
            in("r9") RegionSize as u64,
            // `rcx`/`r11` (RIP/EFLAGS) clobbered by syscall
            out("rcx") _,
            out("r11") _,
            protect = in(reg) Protect as u64,
            alloc_type = in(reg) AllocationType as u64,
        );
    }
    status as i32
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
        let inst_address = Self::syscall_by_ordinal(ntcfg);
        if let Some(ssn) = unsafe { get_ssn(syscall_addr) } {
            return Self {
                ssn,
                name: syscall_name,
                address: syscall_addr as *mut _,
                inst_address: inst_address as *mut _,
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

    fn syscall_by_ordinal(module: Module) -> *const c_void {
        const NT_PFX: u64 = widehash!("Nt\0", &DEFAULT_KEY);
        const ZW_PFX: u64 = widehash!("Zw\0", &DEFAULT_KEY);
        let mut pfx_hash = widehash!("Ff", &DEFAULT_KEY);

        let mut rand_ord = crate::rand_with_max(module.exp_inf.names_len as _);

        // retrieve random functions from NTDLL until we get something that appears to be
        // a syscall (based solely on the presence of a `Zw*`/`Nt*` prefix)
        while pfx_hash != NT_PFX && pfx_hash != ZW_PFX {
            rand_ord = crate::rand_with_max(module.exp_inf.names_len as _);
            let name_addr: *const c_uchar = unsafe {
                module
                    .base
                    .add(*module.exp_inf.names.add(rand_ord as _) as _)
            } as _;

            let fn_name = unsafe { from_ansi_ptr(name_addr) };

            #[cfg(debug_assertions)]
            println!("-> {}", fn_name);

            pfx_hash = rt_widehash!(&fn_name[..2], &DEFAULT_KEY);
        }

        let fn_rva = unsafe { *module.exp_inf.funcs.add(rand_ord as _) };
        let fn_addr = unsafe { module.base.add(fn_rva as _) };

        let mut idx = 0;
        while idx <= OFFSET_RANGE {
            let addr = unsafe { fn_addr.add(idx) as *const u8 };
            if unsafe { from_raw_parts(addr, 0x02) } == [0x0f, 0x05] {
                #[cfg(debug_assertions)]
                println!("syscall @ {:08x?}", addr as *const c_void);

                return addr as _;
            }

            idx += 1;
        }

        #[cfg(debug_assertions)]
        eprintln!("failed to retrieve a valid syscall address");

        ptr::null_mut()
    }
}

unsafe fn get_ssn(addr: *const c_void) -> Option<u32> {
    let opcodes = unsafe { from_raw_parts(addr as *const u8, 0x08) };

    let maybe_ssn = check_opcodes(opcodes);
    if maybe_ssn.is_some() {
        return maybe_ssn;
    }

    // attempt to follow `E9 rel32` displacement directly to the original stub
    let mut curr = addr;
    for j in 0..MAX_JMP_HOPS {
        let next = match unsafe { raw_jmp_target(curr) } {
            Some(next) => next,
            None => break,
        };

        #[cfg(debug_assertions)]
        println!("following 0xE9 hook -> {:08x?} ({j} taken)", next);

        let maybe_ssn = unsafe { check_opcodes(from_raw_parts(next as *const u8, 8)) };
        if maybe_ssn.is_some() {
            return maybe_ssn;
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
        from_raw_parts(
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
