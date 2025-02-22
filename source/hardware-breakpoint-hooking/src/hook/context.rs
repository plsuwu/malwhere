//! Function execution context manipulation for hooks
//!
//! Provides utilities for controlling the execution flow of hooked functions by
//! manipulating their thread context.

use crate::hook::hook::Hook;
use std::ffi::c_void;
use std::ptr::null;
use windows::Win32::System::Diagnostics::Debug::CONTEXT;

/// Static RET opcode to block the execution of a function
///
/// Placed in `.text` section to make sure it will be executable.
#[link_section = ".text"]
static RETURN_INSTRUCTION: [u8; 1] = [0xC3];

/// Blocks the execution of the hooked function by setting `$rip` to a `ret` opcode.
///
/// Prevents the original function from executing while preserving proper stack unwinding.
///
/// # Arguments
///
/// * `ctx` - Mutable reference to the thread context.
pub unsafe fn block_execution(ctx: &mut CONTEXT) {
    ctx.Rip = RETURN_INSTRUCTION.as_ptr() as u64;
}

/// Changes a hooked function's return value by modifying the value in `$rax`.
///
///  # Arguments
///
/// * `ctx` - Mutable reference to the thread context
/// * `value` - The new return value (u64)
pub unsafe fn clobber_return(ctx: &mut CONTEXT, value: u64) {
    ctx.Rax = value;
}

/// Continues execution by setting the resume flag (`RF`) in the `EFLAGS` register.
///
/// # Arguments
///
/// * `ctx` - Mutable reference to the thread context.
pub unsafe fn continue_execution(ctx: &mut CONTEXT) {
    let curr = ctx.EFlags;
    ctx.EFlags = curr | (1 << 16);
}

/// Retrieves a pointer to an argument from the hooked function call at a specified index.
///
/// # Arguments
///
/// * `ctx` - Reference to the thread context
/// * `param_idx` - Index (from 0) of the parameter to read
///
/// # Returns
///
/// Raw pointer (`*mut u8`) to the specified argument in memory
pub unsafe fn get_function_argument(thread_ctx: &CONTEXT, param_idx: u32) -> *mut u8 {
    match param_idx {
        0 => thread_ctx.Rcx as *mut u8,
        1 => thread_ctx.Rdx as *mut u8,
        2 => thread_ctx.R8 as *mut u8,
        3 => thread_ctx.R9 as *mut u8,
        _ => {
            let stack_offset = (param_idx as u64) * std::mem::size_of::<*mut u8>() as u64;
            let addr = thread_ctx.Rsp + stack_offset;

            *(addr as *const *mut u8)
        }
    }
}

/// Sets the value of an argument from the hooked function call at a specified index.
///
/// # Arguments
///
/// * `ctx` - Mutable reference to the thread context
/// * `value` - The new value for the parameter
/// * `param_idx` - Index (from 0) of the parameter to modify
pub unsafe fn set_function_argument(thread_ctx: &mut CONTEXT, value: u64, param_idx: u32) {
    match param_idx {
        0 => thread_ctx.Rcx = value,
        1 => thread_ctx.Rdx = value,
        2 => thread_ctx.R8 = value,
        3 => thread_ctx.R9 = value,
        _ => {
            let stack_offset = (param_idx as u64) * std::mem::size_of::<u64>() as u64;
            let addr = thread_ctx.Rsp + stack_offset;

            *(addr as *mut u64) = value;
        }
    }
}