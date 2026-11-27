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
use common::winstring::{self, rt_str_to_utf16};
use core::ffi::c_void;
use core::ptr::null_mut;
use hooklib::breakpoint::{install_breakpoint, remove_breakpoint};
use hooklib::hook::{block_execution, clobber_return, continue_execution, set_fn_arg};
use hooklib::registers::DRX;

#[cfg(not(test))]
use core::panic::PanicInfo;

use common::alloc::WinHeap;
use common::winapi::{
    AddVectoredExceptionHandler, CONTEXT, ExitProcess, GetLastError, MB_ICONASTERISK,
    MB_ICONQUESTION, MB_OK, MessageBoxW, PVOID, SIZE_T,
};
use common::winapi::{EXCEPTION_POINTERS, LONG, PVECTORED_EXCEPTION_HANDLER};
use common::{hashing::DEFAULT_KEY, widehash};
use hooklib::VectorHandler;
use resolver::syscall::{_NtAllocateVirtualMemory, _NtSetContextThread, NtSyscall};

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
fn example_function(a: u64, b: u64) -> u64 {
    a + b
}

#[unsafe(no_mangle)]
fn detour_function(ctx: &mut CONTEXT) {
    clobber_return(ctx, 9999);
    block_execution(ctx);
}

fn scary_mb(ctx: &mut CONTEXT) {
    let text_str = "scary message";
    let capt_str = "freaky";
    unsafe {
        set_fn_arg(ctx, rt_str_to_utf16(text_str).as_ptr() as _, 1);
        set_fn_arg(ctx, rt_str_to_utf16(capt_str).as_ptr() as _, 2);
        set_fn_arg(ctx, MB_ICONQUESTION as _, 3);
    };
    continue_execution(ctx);
}

fn startup() -> u64 {
    let target_a: *const c_void = example_function as _;
    let detour_a: *const c_void = detour_function as _;

    let handler: PVECTORED_EXCEPTION_HANDLER = VectorHandler as _;
    let _ = unsafe { AddVectoredExceptionHandler(1, handler) };

    let string1 = example_function(10, 20);
    common::println!("string 1: {}", string1);

    install_breakpoint(target_a, detour_a, DRX::Dr0);

    let string1 = example_function(10, 20);
    common::println!("string 2: {}", string1);

    let text_str = "normal message";
    let caption_str = "normal";

    unsafe {
        MessageBoxW(
            null_mut(),
            rt_str_to_utf16(text_str).as_ptr(),
            rt_str_to_utf16(caption_str).as_ptr(),
            MB_ICONASTERISK | MB_OK,
        )
    };

    install_breakpoint(MessageBoxW as _, scary_mb as _, DRX::Dr1);

    unsafe {
        MessageBoxW(
            null_mut(),
            rt_str_to_utf16(text_str).as_ptr(),
            rt_str_to_utf16(caption_str).as_ptr(),
            MB_ICONASTERISK | MB_OK,
        )
    };

    0
}
