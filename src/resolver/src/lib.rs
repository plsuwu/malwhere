#![allow(clippy::missing_safety_doc)]
#![no_std]

pub mod module;
pub mod syscall;
pub mod unhook;

use common::winapi::{LARGE_INTEGER, QueryPerformanceCounter};

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

/// Uses `QueryPerformanceCounter` to seed fastrand with a (more or less)
/// unique, somewhat random value.
pub fn rand_with_max(max: u64) -> u64 {
    let mut ctr = LARGE_INTEGER::default();
    let status = unsafe { QueryPerformanceCounter(&mut ctr) };
    if status == 0x00 {
        return 0x00;
    }

    let seed: u64 = unsafe { ctr.QuadPart }.cast_unsigned();
    let mut rng = fastrand::Rng::with_seed(seed);

    rng.u64(0..max)
}
