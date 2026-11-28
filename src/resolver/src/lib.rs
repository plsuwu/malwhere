#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
#![allow(clippy::missing_safety_doc)]
#![no_std]

pub mod module;
pub mod sync;
pub mod syscall;
pub mod unhook;

#[inline(always)]
#[cfg(all(target_pointer_width = "64", target_arch = "x86_64"))]
pub unsafe fn readgsqword(offset: u64) -> u64 {
    let res: u64;
    unsafe {
        core::arch::asm!(
            // the `.byte 0xE8` is never actually used, but disassemblers are likely to initially
            // read `0xE8` as a `rel32` operand and get junk that looks a bit like the following:
            //
            // ```
            //    push    rax
            //    xor     eax, eax
            //    jz      short near ptr loc_140003825+1
            //
            // loc_140003825:
            //    call    near ptr 0EE0F811Dh
            //    enter   148h, 0C8h                  ;; .byte E8h
            //                                        ;; rdgsbase rax
            //    mov     rax, [rax]
            //    mov     [rsp+198h+var_198], rax
            //
            //    ;; ...
            // ```
            //
            // i think this is a pretty common obfuscation technique and i dont think this is
            // super effective against static scanning tools that would just read the bytes...
            "xor eax,eax",
            "jz 2f",
            ".byte 0xE8",
            "2:",
            "rdgsbase rax",
            "add rax,rcx",
            "mov rax,qword ptr [rax]",
            in("rcx") offset,
            out("rax") res,
        );
    }

    res
}

#[inline(always)]
pub fn current_thread_id() -> usize {
    unsafe { readgsqword(0x48) as _ }
}

/// Use `BCryptGenRandom` to seed
pub fn rand_with_max(max: u64) -> u64 {
    let seed: u64 = common::rand::random_seed();
    let mut rng = fastrand::Rng::with_seed(seed);

    rng.u64(0..max)
}
