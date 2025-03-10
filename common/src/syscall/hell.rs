//! Low-level syscall routing functionality
//!
//! Inline Rust assembly doesn't seem to be the most intuitive so this is a lot of work based on
//! hacky trial-and-error register manipulation. It works as intended, but it's not super modular
//! and clear, unfortunately.

#![allow(unused_assignments)]

use std::arch::asm;

static mut SYSTEM_CALL: u32 = 0;
static mut INSTRUCTION_ADDRESS: u64 = 0;

pub extern "system" fn set_syscall(syscall: u32, address: u64) {
    unsafe {
        SYSTEM_CALL = 0;
        SYSTEM_CALL = syscall;

        INSTRUCTION_ADDRESS = 0;
        INSTRUCTION_ADDRESS = address;
    }
}

/// Performs pre-syscall register manipulation
///
/// ```ignore
/// mov rcx, r10
/// mov eax, <syscall number>
/// syscall
/// ```
///
/// Where `syscall` is called from inside `ntdll.dll` address space (to avoid suspicious `syscall`
/// instructions), this instruction is instead called by a `jmp` instruction to the location of
/// a random `syscall` instruction in `ntdll.dll`:
///
/// ```ignore
/// mov rcx, r10
/// mov eax, 0x18   // `NtAllocateVirtualMemory` SSN
/// jmp qword ptr ss:[ntdll.dll!syscall]
/// ```
///
/// > Note: This function is intended to be called from assembly after storing the syscall's
/// > necessary arguments in the correct registers and pushing the return address to the top of
/// > the stack.
pub unsafe extern "system" fn descend() {
    asm!(
        // Rust keeps compiling this in the most annoying way where jumping to pointer stored in a
        // register causes it to compile a jump to a pointer offset in the // data segment instead
        // of the stack segment.
        //
        // I have no idea what the intended functionality is but this was my workaround (which I
        // doubt is correct).
        "mov qword ptr ss:[rsp+0x10], {1:r}",

        "mov rcx, r10",
        "mov eax, {0:e}",
        "jmp qword ptr ss:[rsp+0x10]",

        in(reg) SYSTEM_CALL,
        in(reg) INSTRUCTION_ADDRESS,
        options(nostack),
    )
}

pub unsafe extern "system" fn syscall_1(arg: u64) -> i32 {
    let mut res: i32 = 0;
    asm!(
        "sub rsp, 0x08",

        "mov r10, rcx",
        "call {d}",

        "add rsp, 0x08",

        in("rcx") arg,

        d = sym descend,
        out("rax") res,

        options(nostack),
    );

    res
}

/// Correctly sets up arguments for a three-parameter syscall (e.g `NtWaitForSingleObject`).
///
/// # Usage
///
/// > Note: A syscall number and address needs to be set by calling `set_syscall` prior to calling
/// > this function!
///
/// Accepts a three-item array of `u64`s - use `std::mem::transmute` or the `as` keyword to cast
/// variables to the correct type:
///
/// ```ignore
/// // set the syscall number and address (automatically
/// // resolved - see the resolver module)
/// set_syscall(ssn, random_address);
///
/// // needs to be mutable for the inline assembly
/// let mut syscall_args: [u64; 3] = [
///     transmute(&mut process_handle),
///     null_mut::<c_void>() as u64,
///
///     // etc...
///
/// ];
///
/// let syscall = syscall_3(mut syscall_args);
/// ```
#[inline(never)]
pub unsafe extern "system" fn syscall_3(args: *const u64) -> i32 {
    let mut res: i32 = 0;

    asm!(
        // Shadow space seems to be automatically allocated by the function call (I think...) so
        // the changes to the stack pointer are meant to account for the pointer workaround in the
        // `descend` function above.
        // "sub rsp, 0x08",

        "mov r10, rcx",
        "call {d}",

        // "add rsp, 0x08",

        in("rcx") *args.wrapping_add(0),
        in("rdx") *args.wrapping_add(1),
        in("r8") *args.wrapping_add(2),

        d = sym descend,
        out("rax") res,

        options(nostack),
    );

    res
}

#[inline(never)]
pub unsafe extern "system" fn syscall_4(args: *const u64) -> i32 {
    let mut res: i32 = 0;

    asm!(
        // "sub rsp, 0x08",

        "mov r10, rcx",
        "call {d}",

        // "add rsp, 0x08",

        in("rcx") *args.wrapping_add(0),
        in("rdx") *args.wrapping_add(1),
        in("r8") *args.wrapping_add(2),
        in("r9") *args.wrapping_add(3),

        d = sym descend,
        out("rax") res,

        options(nostack),
    );

    res
}

/// Correctly sets up arguments for a five-parameter syscall
///
/// # Usage
///
/// > Note: A syscall number and address needs to be set by calling `set_syscall` prior to calling
/// > this function!
///
/// Accepts a five-item array of `u64`s - use `std::mem::transmute` or the `as` keyword to cast
/// variables to the correct type:
///
/// ```ignore
/// // set the syscall number and address (automatically
/// // resolved - see the resolver module)
/// set_syscall(ssn, random_address);
///
/// // needs to be mutable for the inline assembly
/// let mut syscall_args: [u64; 5] = [
///     transmute(&mut process_handle),
///     null_mut::<c_void>() as u64,
///
///     // etc...
///
/// ];
///
/// let syscall = syscall_5(mut syscall_args);
/// ```
pub unsafe extern "system" fn syscall_5(args: *const u64) -> i32 {
    let mut res: i32 = 0;

    asm!(
        "push r11",

        // make room on the stack for the stack segment pointer jump
        "sub rsp, 0x20",

        "mov r10, rcx",
        "call {d}",

        "add rsp, 0x20",
        "pop r11",

        in("rcx") *args.wrapping_add(0),
        in("rdx") *args.wrapping_add(1),
        in("r8") *args.wrapping_add(2),
        in("r9") *args.wrapping_add(3),
        in("r11") *args.wrapping_add(4),

        d = sym descend,

        out("rax") res,
        options(nostack),
    );

    res
}

/// Correctly sets up arguments for a six-parameter syscall
///
/// # Usage
///
/// > Note: A syscall number and address needs to be set by calling `set_syscall` prior to calling
/// > this function!
///
/// Accepts a six-item array of `u64`s - use `std::mem::transmute` or the `as` keyword to cast
/// variables to the correct type:
///
/// ```ignore
/// // set the syscall number and address (automatically
/// // resolved - see the resolver module)
/// set_syscall(ssn, random_address);
///
/// // needs to be mutable for the inline assembly
/// let mut syscall_args: [u64; 6] = [
///     transmute(&mut process_handle),
///     null_mut::<c_void>() as u64,
///
///     // etc...
///
/// ];
///
/// let syscall = syscall_6(mut syscall_args);
/// ```
pub unsafe extern "system" fn syscall_6(args: *const u64) -> i32 {
    let mut res: i32 = 0;

    asm!(
        // space for return address on stack; seems like rustc
        // is auto-allocating some stack space for shadow space
        // for this test case but idk if that will remain true
        // elsewhere

        "push r11",
        "push r10",

        // make room on the stack for the stack segment pointer jump
        "sub rsp, 0x20",

        "mov r10, rcx",

        "call {d}",

        "add rsp, 0x20",
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
        options(nostack),
    );

    res
}

/// Correctly sets up arguments for an eleven-parameter syscall
///
/// # Usage
///
/// > Note: A syscall number and address needs to be set by calling `set_syscall` prior to calling
/// > this function!
///
/// Accepts an eleven-item array of `u64`s - use `std::mem::transmute` or the `as` keyword to cast
/// variables to the correct type:
///
/// ```ignore
/// // set the syscall number and address (automatically
/// // resolved - see the resolver module)
/// set_syscall(ssn, random_address);
///
/// // needs to be mutable for the inline assembly
/// let mut syscall_args: [u64; 11] = [
///     transmute(&mut process_handle),
///     null_mut::<c_void>() as u64,
///
///     // etc...
///
/// ];
///
/// let syscall = syscall_11(mut syscall_args);
/// ```
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

        // make room on the stack for the stack segment pointer jump
        "sub rsp, 0x20",

        "mov r10, rcx",
        "call {d}",

        "add rsp, 0x20",

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
        in("rdi") *args.wrapping_add(6),
        in("r12") *args.wrapping_add(7),
        in("r13") *args.wrapping_add(8),
        in("rsi") *args.wrapping_add(9),
        in("r14") *args.wrapping_add(10),

        d = sym descend,

        out("rax") res,
    );

    res
}

