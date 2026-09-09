#![no_std]
#![no_main]

use core::panic::PanicInfo;

extern crate alloc;
extern crate libc;

use alloc::vec::Vec;
pub use utilities::heap::*;

// #[unsafe(no_mangle)]
// pub extern "C" fn rust_eh_personality() {}

#[unsafe(no_mangle)]
pub extern "C" fn main(_: isize, _: *const *const u8) -> isize {
    const H: &str = "hiiii\n\0";
    let v: Vec<u8> = Vec::from([0x02]);

    unsafe {
        libc::printf(H.as_ptr() as _);
        libc::printf(v.as_ptr() as _);
    }

    0
}

#[cfg_attr(not(test), panic_handler)]
fn panic(_: &PanicInfo<'_>) -> ! {
    unsafe { libc::exit(1) }
}
