//! `mingw` links its own runtime, defines a `mainCRTStartup`, and pre-compiled unwinding info,
//! so we do some conditional compilation to provide what MSVC and mingw both expect.
//!
//! Ultimately MSVC compiles this down way smaller (due to liballoc) and is generally less annoying
//! so far, so we might wind up switching to `xwin` exclusively if this holds.

#![allow(non_snake_case)]
#![no_std]
#![no_main]
#![windows_subsystem = "console"]

extern crate alloc;
use alloc::string::{String, ToString};
use core::ffi::c_void;

#[cfg(not(test))]
use core::panic::PanicInfo;

use common::alloc::WinHeap;
use common::winapi::{
    AddVectoredExceptionHandler, CONTEXT, ExitProcess, GetLastError, PVOID, SIZE_T,
};
use common::winapi::{EXCEPTION_POINTERS, LONG, PVECTORED_EXCEPTION_HANDLER};
use common::{hashing::DEFAULT_KEY, widehash};
use hooklib::{DRX, VectorHandler, set_hardware_breakpoint};
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

#[unsafe(no_mangle)]
fn example_function() -> String {
    "normal return".to_string()
}

#[unsafe(no_mangle)]
fn detour_function() -> String {
    "scary return".to_string()
}

fn startup() -> u64 {
    let addr: *const c_void = example_function as _;
    let detour_addr: *const c_void = detour_function as _;

    let handler: PVECTORED_EXCEPTION_HANDLER = VectorHandler as _;
    let _ = unsafe { AddVectoredExceptionHandler(1, handler) };

    let string1 = example_function();
    common::println!("string 1: {}", string1);

    set_hardware_breakpoint(addr, detour_addr, DRX::Dr0);

    let string1 = example_function();
    common::println!("string 2: {}", string1);

    0
}
