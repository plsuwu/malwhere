use core::ffi::c_void;

use common::prelude::*;
use common::winapi::*;
use resolver::syscall::{_NtGetContextThread, _NtSetContextThread};

use crate::hook::HookTab;
use crate::registers::{DRCtl, DRX};
use crate::{get_thread_ctx_sc, set_thread_ctx_sc};

pub fn install_breakpoint(
    target: *const core::ffi::c_void,
    detour: *const c_void,
    reg: DRX,
) {
    #[cfg(debug_assertions)]
    println!("installing breakpoint: DRX={}", reg as u64);

    let mut thread_ctx = CONTEXT {
        ContextFlags: CONTEXT_DEBUG_REGISTERS,
        ..Default::default()
    };

    let current_thread_handle: HANDLE = (-2isize).cast_unsigned() as _;
    _NtGetContextThread(&get_thread_ctx_sc(), current_thread_handle, &mut thread_ctx);

    reg.set(&mut thread_ctx, target as _);
    let mut dr_ctl = DRCtl::from_bits(thread_ctx.Dr7).unwrap_or(DRCtl::empty());
    dr_ctl.enable(&mut thread_ctx, reg);

    HookTab::install(reg.into(), detour);

    // write updates
    _NtSetContextThread(&set_thread_ctx_sc(), current_thread_handle, &mut thread_ctx);
}

pub fn remove_breakpoint(reg: DRX) {
    #[cfg(debug_assertions)]
    println!("removing breakpoint: DRX={}", reg as u64);

    let mut thread_ctx = CONTEXT {
        ContextFlags: CONTEXT_DEBUG_REGISTERS,
        ..Default::default()
    };

    let current_thread_handle: HANDLE = (-2isize).cast_unsigned() as _;
    _NtGetContextThread(&get_thread_ctx_sc(), current_thread_handle, &mut thread_ctx);

    reg.clear(&mut thread_ctx);
    let mut dr_ctl = DRCtl::from_bits(thread_ctx.Dr7).unwrap_or(DRCtl::empty());
    dr_ctl.disable(&mut thread_ctx, reg);

    HookTab::remove(reg.into());

    // write updates
    _NtSetContextThread(&set_thread_ctx_sc(), current_thread_handle, &mut thread_ctx);
}
