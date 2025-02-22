mod hook;
use hook::context;

use core::ffi::c_void;

use crate::hook::hook::{Hook};
use windows::Win32::System::Diagnostics::Debug::CONTEXT;
use crate::hook::registers::DebugRegister::{Dr0, Dr1, Dr2, Dr3};

#[no_mangle]
extern "system" fn target_a(a: usize, b: usize) -> usize {
    a + b
}

#[no_mangle]
extern "system" fn target_b(a: usize, b: usize) -> usize {
    a * b
}

#[no_mangle]
extern "system" fn detour_a(ctx: &mut CONTEXT) {
    let ret = 99u64;
    unsafe {

        context::block_execution(ctx);
        context::clobber_return(ctx, ret);
    }
}

#[no_mangle]
extern "system" fn detour_b(ctx: &mut CONTEXT) {
    set_param!(ctx, 50, 0);
    set_param!(ctx, 3, 1);

    unsafe { context::continue_execution(ctx) };
}



fn main() -> anyhow::Result<()> {

    println!("\n[+] Func A: {} + {} = {}", 1, 2, target_a(1, 2));
    println!("[+] Func B: {} * {} = {}", 1, 2, target_b(1, 2));

    let detour_a_ptr = detour_a as *const c_void;
    let detour_b_ptr = detour_b as *const c_void;

    let target_a_ptr = target_a as *const c_void;
    let target_b_ptr = target_b as *const c_void;

    let mut hook_0 = Hook::new(detour_a_ptr, target_a_ptr)?;
    let mut hook_1 = Hook::new(detour_b_ptr, target_b_ptr)?;

    let _h0 = hook_0.install(Dr0)?;
    let _h1 = hook_1.install(Dr1)?;

    println!("\n------------------------------");
    println!(" Installed hooks in Dr0 + Dr1");
    println!("------------------------------\n");

    println!("[+] Func A: {} + {} = {}", 1, 2, target_a(1, 2));
    println!("[+] Func B: {} * {} = {}", 1, 2, target_b(1, 2));


    Ok(())
}
