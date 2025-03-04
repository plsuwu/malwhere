use std::arch::asm;

static mut SYSTEM_CALL: u32 = 0;
static mut INSTRUCTION_ADDRESS: u64 = 0;

#[cfg(target_arch = "x86_64")]
pub extern "system" fn set_syscall(syscall: u32, address: u64) {
    unsafe {
        SYSTEM_CALL = 0;
        SYSTEM_CALL = syscall;

        INSTRUCTION_ADDRESS = 0;
        INSTRUCTION_ADDRESS = address;
    }
}

pub unsafe extern "system" fn descend() {
    asm!(
        "mov qword ptr ss:[rsp+0x10], {1:r}",

        "mov rcx, r10",
        "mov eax, {0:e}",
        "jmp qword ptr ss:[rsp+0x10]",

        in(reg) SYSTEM_CALL,
        in(reg) INSTRUCTION_ADDRESS,
        options(nostack),
    )
}


/*
    this doesn't feel ideal given the fact we have to load each arg into
    its own register like this.

    I'm certain there's a good workaround here but I have not figured it
    out yet...
 */
pub unsafe extern "system" fn syscall_6(mut args: [u64; 6]) -> i32 {
    let mut res: i32 = 0;

    asm!(
        "sub rsp, 0x08",

        "mov qword ptr ss:[rsp+0x28], r11",
        "mov qword ptr ss:[rsp+0x20], r10",
        "mov r10, rcx",

        "call {d}",

        "add rsp, 0x08",
        in("rcx") args[0],
        in("rdx") args[1],
        in("r8") args[2],
        in("r9") args[3],
        in("r10") args[4],
        in("r11") args[5],

        d = sym descend,

        out("rax") res,
        options(nostack),
    );

    res
}

