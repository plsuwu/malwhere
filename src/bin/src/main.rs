//! `mingw` links its own runtime, defines a `mainCRTStartup`, and pre-compiled unwinding info,
//! so we do some conditional compilation to provide what MSVC and mingw both expect.
//!
//! Ultimately MSVC compiles this down way smaller (due to liballoc) and is generally less annoying
//! so far, so we might wind up switching to `xwin` exclusively if this holds.

#![allow(non_snake_case)]
#![no_std]
#![no_main]
#![windows_subsystem = "console"]

use core::ffi::c_void;

#[cfg(not(test))]
use core::panic::PanicInfo;

use common::alloc::WinHeap;
use common::winapi::{ExitProcess, GetLastError, PVOID, SIZE_T};
use common::{hashing::DEFAULT_KEY, widehash};
use resolver::syscall::{_NtAllocateVirtualMemory, NtSyscall};

#[global_allocator]
static GLOBAL: WinHeap = WinHeap;

#[cfg(not(test))]
#[panic_handler]
fn panic(panic_info: &PanicInfo<'_>) -> ! {
    #[cfg(debug_assertions)]
    common::eprintln!("failed: {:#?}", panic_info);
    unsafe { common::winapi::ExitProcess(1) };
}

// liballoc's precompiled unwind info references `rust_eh_personality` (even under
// `panic = "abort"`, where it is unreachable), and mingw has no std to provide it
#[cfg(target_env = "gnu")]
#[unsafe(no_mangle)]
extern "C" fn rust_eh_personality() {}

// mingw's `CRT2.o` also already defines a `mainCRTStartup`, and prefers to invoke
// a standard `main` entrypoint instead
#[cfg(target_env = "gnu")]
#[unsafe(no_mangle)]
extern "C" fn main(_argc: i32, _argv: *mut *mut core::ffi::c_char) -> i32 {
    startup() as i32
}

#[cfg(target_env = "msvc")]
#[link(name = "vcruntime")]
#[link(name = "ucrt")]
unsafe extern "C" {}

#[cfg(target_env = "msvc")]
#[unsafe(no_mangle)]
fn mainCRTStartup() -> u64 {
    startup()
}

fn startup() -> u64 {
    let syscall_hash = widehash!("NtAllocateVirtualMemory\0", &DEFAULT_KEY);
    let syscall_cfg = NtSyscall::new(syscall_hash);

    #[cfg(debug_assertions)]
    common::println!("SYSCALL: {:#?}", syscall_cfg);

    let mut allocation: PVOID = core::ptr::null_mut();

    let mut region_sz: SIZE_T = 123;
    let status = unsafe {
        _NtAllocateVirtualMemory(
            &syscall_cfg,
            (-1i64).cast_unsigned() as *const c_void as _,
            &mut allocation,
            0x00,
            (&mut region_sz) as _,
            0x00001000 | 0x00002000,
            0x04,
        )
    };

    if status != 0x00 {
        common::eprintln!("failed: {:?}", status);
        common::eprintln!("lasterr: {:?}", unsafe { GetLastError() });
        unsafe {
            ExitProcess(1);
        }
    }

    #[cfg(debug_assertions)]
    {
        common::println!("status: {:08x?}", status);
        common::println!("alloc: {:p}", allocation);
        common::println!("region: {}", region_sz);
    }

    syscall_cfg.ssn as _
}
