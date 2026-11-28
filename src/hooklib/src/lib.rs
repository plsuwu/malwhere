#![no_std]
#![feature(thread_local)]
#![allow(clippy::missing_safety_doc)]
#![allow(
    non_camel_case_types,
    non_snake_case,
    non_upper_case_globals,
    unused_assignments
)]

use core::cell::Cell;
use core::cell::LazyCell;

use common::prelude::*;
use common::winapi::*;
use resolver::syscall::NtSyscall;

use crate::hook::HookTab;

pub mod breakpoint;
pub mod hook;
pub mod registers;

/// Lazily-initialized syscalls for `NtGetContextThread`/`NtSetContextThread` addresses
static mut CONTEXT_SC: LazyCell<[NtSyscall; 3]> = LazyCell::new(|| {
    [
        NtSyscall::new(widehash!("NtGetContextThread\0")),
        NtSyscall::new(widehash!("NtSetContextThread\0")),
        NtSyscall::new(widehash!("NtOpenThread\0")),
    ]
});

#[inline]
fn get_thread_ctx_sc() -> NtSyscall {
    unsafe { CONTEXT_SC[0] }
}

#[inline]
fn set_thread_ctx_sc() -> NtSyscall {
    unsafe { CONTEXT_SC[1] }
}

/// Re-entrancy guarding (?) mechanism for detour execution within a VEH
///
/// Avoids syscall round trips and a handful of other pain points around "manually"
/// disabling/re-enabling breakpoints in a VEH.
///
/// > Not 100% certain this works perfectly but I can't see why not...
#[thread_local]
static DETOUR: Detour = const {
    Detour {
        inner: Cell::new(0),
    }
};

struct Detour {
    inner: Cell<u8>,
}

impl Detour {
    #[inline]
    pub fn is_locked(&self, mask: u8) -> bool {
        self.inner.get() & mask != 0
    }

    // TODO: this could be turned into a closure that lets us `unlock` on scope drop,
    //       but i cannot be bothered with too much complexity for now...
    #[inline]
    pub fn lock(&self, mask: u8) {
        self.inner.set(self.inner.get() | mask);
    }

    #[inline]
    pub fn unlock(&self, mask: u8) {
        self.inner.set(self.inner.get() & !mask);
    }
}

#[inline]
fn detour_guard() -> &'static Detour {
    &DETOUR
}

pub unsafe extern "system" fn VectorHandler(pExceptionInfo: *mut EXCEPTION_POINTERS) -> LONG {
    let ex_record = unsafe { *(*pExceptionInfo).ExceptionRecord };
    if ex_record.ExceptionCode != EXCEPTION_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    // NOTE: we take a mutable reference of the `ContextRecord` here to avoid creating a local
    //       copy that doesn't actually update
    let ctx = unsafe { (*pExceptionInfo).ContextRecord.as_mut().unwrap() };

    let ex_addr = ex_record.ExceptionAddress as u64;
    let Some(slot) = [ctx.Dr0, ctx.Dr1, ctx.Dr2, ctx.Dr3]
        .iter()
        .position(|&addr| addr == ex_addr)
    else {
        return EXCEPTION_CONTINUE_SEARCH;
    };

    #[cfg(debug_assertions)]
    println!(
        "matched a detoured function: {:016x?} (index={})",
        ex_addr, slot
    );

    let mask = 1u8 << slot;
    let guard = detour_guard();

    // if the detour for this slot is already running on this thread,
    // avoid dispatching the detour function again
    if guard.is_locked(mask) {
        ctx.EFlags |= 1 << 16;
        return EXCEPTION_CONTINUE_EXECUTION;
    }

    let detour_addr = HookTab::detour_at(slot);
    let detour: fn(ctx: &mut CONTEXT) = unsafe { core::mem::transmute(detour_addr) };

    guard.lock(mask);
    detour(ctx);
    guard.unlock(mask);

    ctx.EFlags |= 1 << 16; // set RF
    EXCEPTION_CONTINUE_EXECUTION
}

pub struct DESCRIPTOR_ENTRY {
    /// Pointer to next linked list element
    pub next: *mut DESCRIPTOR_ENTRY,
    /// Pointer to previous linked list element
    pub prev: *mut DESCRIPTOR_ENTRY,
    /// Address of the breakpoint
    pub address: PVOID,
    /// Index of the hardware debug register (Dr0 - Dr3)
    pub drx: registers::DRX,
    /// ID of the thread in which the breakpoint is installed
    pub thread_id: DWORD,
    /// callback function pointer (i.e. detour function)
    pub callback_fn: PVOID,
    /// flag to indicate node as processed in the VEH function
    pub processed: bool,
}
