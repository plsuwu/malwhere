#![allow(non_snake_case)]
#![no_std]
#![no_main]
#![windows_subsystem = "console"]

#[cfg(not(test))]
use core::panic::PanicInfo;

use common::alloc::WinHeap;
use common::{hashing::DEFAULT_KEY, widehash};
use resolver::syscall::NtSyscall;

#[global_allocator]
static GLOBAL: WinHeap = WinHeap;

#[link(name = "vcruntime")]
#[link(name = "ucrt")]
unsafe extern "C" {}

#[cfg(not(test))]
#[panic_handler]
fn panic(panic_info: &PanicInfo<'_>) -> ! {
    #[cfg(debug_assertions)]
    common::eprintln!("failed: {:#?}", panic_info);

    unsafe { common::winapi::ExitProcess(1) };
}

#[unsafe(no_mangle)]
fn mainCRTStartup() -> u64 {
    let syscall_hash = widehash!("NtTerminateProcess\0", &DEFAULT_KEY);
    let syscall_cfg = NtSyscall::new(syscall_hash);

    #[cfg(debug_assertions)]
    common::println!("SYSCALL: {:#?}", syscall_cfg);

    syscall_cfg.ssn as _
}
