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
use alloc::vec::Vec;
use common::winstring::rt_str_to_utf16;
use core::ffi::c_void;
use core::hint::black_box;
use core::ptr::null_mut;
use hooklib::breakpoint::install_breakpoint;
use hooklib::hook::{block_execution, clobber_return, continue_execution, set_fn_arg};
use hooklib::registers::DRX;

use common::alloc::WinHeap;
use common::winapi::PVECTORED_EXCEPTION_HANDLER;
use common::winapi::{AddVectoredExceptionHandler, MessageBoxW};
use common::winapi::{CONTEXT, MB_ICONEXCLAMATION, MB_ICONINFORMATION, MB_OK, MB_YESNO};
use hooklib::VectorHandler;

#[global_allocator]
static GLOBAL: WinHeap = WinHeap;

#[cfg(not(test))]
use core::panic::PanicInfo;

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

#[inline(never)]
pub fn example_function(a: u64, b: u64) -> u64 {
    a + b
}

pub fn detour_function(ctx: &mut CONTEXT) {
    clobber_return(ctx, 9999);
    block_execution(ctx);
}

fn scary_mb(ctx: &mut CONTEXT) {
    // ensure the allocation lives long enough via `Vec::leak`/`Box::leak`
    let scary_text = Vec::leak(rt_str_to_utf16("scary message"));
    let scary_caption = Vec::leak(rt_str_to_utf16("freaky"));

    unsafe {
        set_fn_arg(ctx, scary_text.as_ptr() as _, 1);
        set_fn_arg(ctx, scary_caption.as_ptr() as _, 2);
        set_fn_arg(ctx, (MB_ICONEXCLAMATION | MB_YESNO) as _, 3);
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
    install_breakpoint(MessageBoxW as _, scary_mb as _, DRX::Dr1);

    // force indirect call wrapped in a black box to avoid devirtualisation/CSE in release builds
    let f: fn(u64, u64) -> u64 = black_box(example_function);
    let r = f(black_box(10), black_box(20));
    common::println!("string 2: {}", r);

    let text_str_normal = "normal message";
    let caption_str = "normal";

    unsafe {
        MessageBoxW(
            null_mut(),
            rt_str_to_utf16(text_str_normal).as_ptr(),
            rt_str_to_utf16(caption_str).as_ptr(),
            MB_ICONINFORMATION | MB_OK,
        )
    };

    0
}
