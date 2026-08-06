#![no_std]
#![no_main]
#![windows_subsystem = "console"]

use core::panic::PanicInfo;

use importer::lookup::module_by_hash;
use utilities::bindings::{ExitProcess, GetLastError};
use utilities::{obf_wstr, println};

#[link(name = "vcruntime")]
#[link(name = "ucrt")]
unsafe extern "C" {}


#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    let err = unsafe { GetLastError() };
    println!("{:02x?}", err);

    unsafe { ExitProcess(1) };
}

#[unsafe(no_mangle)]
fn mainCRTStartup() -> u64 {

    let ntdll_hash = obf_wstr!("ntdll.dll");

    let maybe_handle = module_by_hash(ntdll_hash);
    if let Some(handle) = maybe_handle {
        println!("found module @: {:016x?}", handle);
    }

    0
}