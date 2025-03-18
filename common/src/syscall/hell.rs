//! Low-level indirect syscall functionality ("Hell's Hall" implementation)
//!
//! Inline Rust assembly doesn't seem to be the most intuitive so this is a lot of work based on
//! hacky trial-and-error register manipulation. It works as intended for now, but it's not super
//! modular or clear, and some very inconsequential statements prior to calling one of the below
//! functions containing an `asm!` macro can cause them to break for no clear reason; I currently
//! don't understand *why* this happens - e.g:
//!
//! Making a `NtProtectVirtualMemory` call will return an `NTSTATUS` of `0xC000000D` (i.e
//! `STATUS_INVALID_PARAMETER`), but creating a completely unused format string that renders an
//! arbitrary pointer as a 16-digit hex string (e.g `_ = format!("{:016x?}", "a".as_ptr())`) will
//! pass the exact same set of arguments to the `NtProtectVirtualMemory` syscall which will
//! complete successfully. ASLR aside, it does not appear that the arguments have meaningfully
//! changed when stepping through the program in a debugger.
//!
//! :(

#![allow(unused_assignments)]

use core::arch::asm;

static mut SYSTEM_CALL: u32 = 0;
static mut INSTRUCTION_ADDRESS: u64 = 0;

pub extern "system" fn set_syscall(syscall: u32, address: u64) {

    unsafe {
        SYSTEM_CALL = syscall;
        INSTRUCTION_ADDRESS = address;
    }

}

pub extern "system" fn clear_syscall() {
    unsafe {
        SYSTEM_CALL = 0;
        INSTRUCTION_ADDRESS = 0;
    }
}

#[inline(never)]
pub unsafe extern "system" fn descend() {
    asm!(

        "mov qword ptr ss:[rsp+0x08], {1:r}",

        "mov rcx, r10",
        "mov eax, {0:e}",
        "jmp qword ptr ss:[rsp+0x08]",

        inout(reg) SYSTEM_CALL => _,
        inout(reg) INSTRUCTION_ADDRESS => _,

        options(nostack)
    );
}

#[inline(never)]
pub unsafe extern "system" fn syscall_1(arg: u64) -> i32 {
    let mut res: i32 = 0;
    asm!(

        "mov r10, rcx",
        "call {d}",

        in("rcx") arg,

        d = sym descend,
        out("rax") res,

        clobber_abi("system"),
    );

    res
}

#[inline(never)]
pub unsafe extern "system" fn syscall_3(args: *const u64) -> i32 {
    let mut res: i32 = 0;
    asm!(
        "mov r10, rcx",
        "call {d}",

        in("rcx") *args.wrapping_add(0),
        in("rdx") *args.wrapping_add(1),
        in("r8") *args.wrapping_add(2),

        d = sym descend,
        out("rax") res,

        clobber_abi("system"),
    );

    res
}

#[inline(never)]
pub unsafe extern "system" fn syscall_4(args: *const u64) -> i32 {
    let mut res: i32 = 0;

    asm!(

        "mov r10, rcx",
        "call {d}",

        in("rcx") *args.wrapping_add(0),
        in("rdx") *args.wrapping_add(1),
        in("r8") *args.wrapping_add(2),
        in("r9") *args.wrapping_add(3),

        d = sym descend,
        out("rax") res,

        clobber_abi("system"),
    );

    res
}

#[inline(never)]
pub unsafe extern "system" fn syscall_5(args: *const u64) -> i32 {
    let mut res: i32 = 0;
    asm!(
    /*```
        asquared31415 — 3/15/25, 4:53 AM
        whenever you use a call you likely need to clobber_abi
        [4:54 AM]
        also at the bottom of the page i linked is the options:
        > nostack means that the asm code does not push any data onto the stack.
        [4:55 AM]
        "i fix it by the end of the asm" is not sufficient for this option
        [4:55 AM]
        the stack being fixed by the end of the asm is just the default assumption
    ```*/
        "push r11",

        "mov r10, rcx",

        "sub rsp, 0x18",
        "push r11",         // we push some random garbage to the stack here which
                            // is overwritten with the address of the syscall instruction
        "call {d}",

        "pop r11",          // pop the address back into `r11` before resetting the stack
        "add rsp, 0x18",

        "pop r11",

        in("rcx") *args.wrapping_add(0),
        in("rdx") *args.wrapping_add(1),
        in("r8") *args.wrapping_add(2),
        in("r9") *args.wrapping_add(3),
        in("r11") *args.wrapping_add(4),

        d = sym descend,

        out("rax") res,

        clobber_abi("system"),

    );

    res
}

#[inline(never)]
pub unsafe extern "system" fn syscall_6(args: *const u64) -> i32 {
    let mut res: i32 = 0;

    asm!(
        "push r11",
        "push r10",

        "mov r10, rcx",

        "sub rsp, 0x18",
        "push r11",
        "call {d}",

        "pop r11",
        "add rsp, 0x18",

        "pop r10",
        "pop r11",

        in("rcx") *args.wrapping_add(0),
        in("rdx") *args.wrapping_add(1),
        in("r8") *args.wrapping_add(2),
        in("r9") *args.wrapping_add(3),
        in("r10") *args.wrapping_add(4),
        in("r11") *args.wrapping_add(5),

        d = sym descend,

        out("rax") res,

        clobber_abi("system"),
    );

    res
}

#[inline(never)]
pub unsafe extern "system" fn syscall_7(args: *const u64) -> i32 {
    let mut res: i32 = 0;

    asm!(
        "push r12",
        "push r11",
        "push r10",

        "sub rsp, 0x18",

        "mov r10, rcx",
        "push r11",
        "call {d}",

        "pop r11",

        "add rsp, 0x18",

        "pop r10",
        "pop r11",
        "pop r12",

        in("rcx") *args.wrapping_add(0),
        in("rdx") *args.wrapping_add(1),
        in("r8") *args.wrapping_add(2),
        in("r9") *args.wrapping_add(3),
        in("r10") *args.wrapping_add(4),
        in("r11") *args.wrapping_add(5),
        inout("r12") *args.wrapping_add(6) => _,

        d = sym descend,

        out("rax") res,

        clobber_abi("system"),
    );

    res
}

#[inline(never)]
pub unsafe extern "system" fn syscall_11(args: *const u64) -> i32 {
    let mut res: i32 = 0;

    asm!(

        "push r14",
        "push rsi",
        "push r13",
        "push r12",
        "push rdi",
        "push r11",
        "push r10",

        "sub rsp, 0x18",

        "mov r10, rcx",
        "push r11",

        "call {d}",

        "pop r13",

        "add rsp, 0x18",

        "pop r13",
        "pop r13",
        "pop r13",
        "pop r13",
        "pop r13",
        "pop r13",
        "pop r13",

        in("rcx") *args.wrapping_add(0),
        in("rdx") *args.wrapping_add(1),
        in("r8") *args.wrapping_add(2),
        in("r9") *args.wrapping_add(3),
        in("r10") *args.wrapping_add(4),
        in("r11") *args.wrapping_add(5),
        inout("rdi") *args.wrapping_add(6) => _,
        inout("r12") *args.wrapping_add(7) => _,
        inout("r13") *args.wrapping_add(8) => _,
        inout("rsi") *args.wrapping_add(9) => _,
        inout("r14") *args.wrapping_add(10) => _,

        d = sym descend,

        out("rax") res,

        clobber_abi("system"),
    );

    res
}

