#![allow(clippy::missing_safety_doc)]
#![no_std]

pub mod unhook;
pub mod module;
pub mod syscall;

// TODO replace this with something that doesn't look so obviously like PEB
// pointer retrieval
//
//      -> see e.g. https://synawk.com/blog/peb-obfuscation-malware-dev-0x4
#[inline]
#[cfg(all(target_pointer_width = "64", target_arch = "x86_64"))]
pub unsafe fn readgsqword(offset: u64) -> u64 {
    let res;
    unsafe {
        core::arch::asm!(
            "mov {}, qword ptr gs:[{:e}]",
            out(reg) res,
            in(reg) offset,
            options(nostack, pure, readonly, preserves_flags)
        );
    }
    res
}
