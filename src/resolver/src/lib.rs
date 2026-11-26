#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
#![allow(clippy::missing_safety_doc)]
#![no_std]

pub mod module;
pub mod syscall;
pub mod sync;
pub mod unhook;

// TODO replace these register calls with something that doesn't look so obviously like
//      e.g. PEB pointer retrieval or whatever
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

/// Use `BCryptGenRandom` to seed
pub fn rand_with_max(max: u64) -> u64 {
    let seed: u64 = common::rand::random_seed();
    let mut rng = fastrand::Rng::with_seed(seed);

    rng.u64(0..max)
}
