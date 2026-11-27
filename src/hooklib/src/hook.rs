use common::winapi::CONTEXT;
use core::ffi::c_void;
use resolver::sync::Mutex;

pub(crate) struct HookTab {
    dr: [u64; 4],
}

pub(crate) static HOOKS: Mutex<HookTab> = Mutex::new(HookTab { dr: [0u64; 4] });

impl HookTab {
    pub(crate) fn install(slot: usize, addr: *const c_void) {
        let mut hooks = HOOKS.lock();
        hooks.dr[slot] = addr as u64;
    }

    pub(crate) fn remove(slot: usize) {
        let mut hooks = HOOKS.lock();
        hooks.dr[slot] = core::ptr::null::<c_void>() as u64;
    }

    pub(crate) fn detour_at(slot: usize) -> u64 {
        let hooks = HOOKS.lock();
        hooks.dr[slot]
    }
}

#[unsafe(link_section = ".text")]
static RET_INST: [u8; 1] = [0xC3];

pub fn block_execution(ctx: &mut CONTEXT) {
    ctx.Rip = RET_INST.as_ptr() as u64;
}

pub fn continue_execution(ctx: &mut CONTEXT) {
    ctx.EFlags |= 1 << 16;
}

pub fn clobber_return(ctx: &mut CONTEXT, new_val: u64) {
    ctx.Rax = new_val;
}

pub unsafe fn get_fn_arg(thread_ctx: &CONTEXT, param_idx: u32) -> *mut u8 {
    match param_idx {
        0 => thread_ctx.Rcx as *mut u8,
        1 => thread_ctx.Rdx as *mut u8,
        2 => thread_ctx.R8 as *mut u8,
        3 => thread_ctx.R9 as *mut u8,
        _ => {
            let stack_offset = (param_idx as u64) * core::mem::size_of::<*mut u8>() as u64;
            let addr = thread_ctx.Rsp + stack_offset;

            unsafe { *(addr as *const *mut u8) }
        }
    }
}

pub unsafe fn set_fn_arg(thread_ctx: &mut CONTEXT, value: u64, param_idx: u32) {
    match param_idx {
        0 => thread_ctx.Rcx = value,
        1 => thread_ctx.Rdx = value,
        2 => thread_ctx.R8 = value,
        3 => thread_ctx.R9 = value,
        _ => {
            let stack_offset = (param_idx as u64) * core::mem::size_of::<u64>() as u64;
            let addr = thread_ctx.Rsp + stack_offset;

            unsafe { *(addr as *mut u64) = value };
        }
    }
}

#[macro_export]
macro_rules! get_arg {
    ($ctx:expr, $num:expr) => {
        unsafe { $crate::hook::get_fn_arg($ctx, $num) }
    };
}

#[macro_export]
macro_rules! set_arg {
    ($ctx:expr, $val:expr, $num:expr) => {
        unsafe { $crate::hook::set_fn_arg($ctx, $val, $num) }
    };
}
