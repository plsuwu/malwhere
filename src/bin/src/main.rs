#![no_std]
#![no_main]
#![windows_subsystem = "console"]

use core::panic::PanicInfo;

use common::alloc::WinHeap;
use common::{hashing::DEFAULT_KEY, resolver::NtSyscall, widehash};

#[global_allocator]
static GLOBAL: WinHeap = WinHeap;

#[link(name = "vcruntime")]
#[link(name = "ucrt")]
unsafe extern "C" {}

#[panic_handler]
fn panic(panic_info: &PanicInfo<'_>) -> ! {
    common::eprintln!("failed: {:#?}", panic_info);
    loop {}
}


#[unsafe(no_mangle)]
fn mainCRTStartup() -> u64 {
    let syscall_hash = widehash!("NtTerminateProcess\0", &DEFAULT_KEY);
    let syscall_cfg = NtSyscall::new(syscall_hash);

    if syscall_cfg.ssn > 0 {
        return 99;
    }

    1
}
