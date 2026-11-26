#![allow(clippy::missing_safety_doc)]
#![allow(non_camel_case_types, non_snake_case, non_upper_case_globals)]
#![no_std]

use core::cell::LazyCell;
use core::ffi::c_void;

use bitflags::bitflags;

use common::hashing::DEFAULT_KEY;
use common::prelude::*;
use common::winapi::*;
use resolver::sync::{Mutex, MutexGuard};
use resolver::syscall::NtSyscall;
use resolver::syscall::syscall_2;

static mut CONTEXT_SC: LazyCell<[NtSyscall; 2]> = LazyCell::new(|| {
    [
        NtSyscall::new(widehash!("NtGetContextThread\0", &DEFAULT_KEY)),
        NtSyscall::new(widehash!("NtSetContextThread\0", &DEFAULT_KEY)),
    ]
});

struct HookTab {
    dr: [usize; 4],
}

static HOOKS: Mutex<HookTab> = Mutex::new(HookTab { dr: [0; 4] });

fn install(slot: usize, addr: *const c_void) {
    let mut hooks = HOOKS.lock();
    hooks.dr[slot] = addr as usize;
}

fn on_breakpoint() {
    let hooks = HOOKS.lock();
    let _ = hooks.dr[0];
}

#[inline]
fn get_thread_ctx_sc() -> NtSyscall {
    unsafe { CONTEXT_SC[0] }
}

#[inline]
fn set_thread_ctx_sc() -> NtSyscall {
    unsafe { CONTEXT_SC[1] }
}

pub fn _NtGetContextThread(sc: &NtSyscall, ThreadHandle: HANDLE, ThreadContext: *mut CONTEXT) {
    let status = unsafe { syscall_2(sc, ThreadHandle as _, ThreadContext as _) };
    println!("get_thread_context: 0x{:08x?}", status);
}

pub fn _NtSetContextThread(sc: &NtSyscall, ThreadHandle: HANDLE, ThreadContext: *mut CONTEXT) {
    let status = unsafe { syscall_2(sc, ThreadHandle as _, ThreadContext as _) };
    println!("set_thread_context: 0x{:08x?}", status);
}

#[derive(Clone, Copy, Debug)]
pub enum DRX {
    Dr0,
    Dr1,
    Dr2,
    Dr3,
}

impl DRX {
    pub fn from_hash(value: u64) -> Self {
        if value == widehash!("DR1", &DEFAULT_KEY) {
            Self::Dr1
        } else if value == widehash!("DR2", &DEFAULT_KEY) {
            Self::Dr2
        } else if value == widehash!("DR3", &DEFAULT_KEY) {
            Self::Dr3
        } else {
            Self::Dr0
        }
    }
}

pub fn set_hardware_breakpoint(target: *const core::ffi::c_void, detour: *const c_void, reg: DRX) {
    let mut thread_ctx = CONTEXT {
        ContextFlags: CONTEXT_DEBUG_REGISTERS,
        ..Default::default()
    };

    let current_thread_handle: HANDLE = (-2isize).cast_unsigned() as _;
    _NtGetContextThread(&get_thread_ctx_sc(), current_thread_handle, &mut thread_ctx);

    let mut dr_ctl = DRCtl::from_bits(thread_ctx.Dr7).unwrap_or(DRCtl::empty());
    match reg {
        DRX::Dr0 => {
            thread_ctx.Dr0 = target as _;
            install(0, detour);

            dr_ctl.insert(DRCtl::L0);
        }
        DRX::Dr1 => {
            thread_ctx.Dr1 = target as _;
            dr_ctl.insert(DRCtl::L1);

            install(1, detour);
        }
        DRX::Dr2 => {
            thread_ctx.Dr2 = target as _;
            dr_ctl.insert(DRCtl::L2);

            install(2, detour);
        }
        DRX::Dr3 => {
            thread_ctx.Dr3 = target as _;
            dr_ctl.insert(DRCtl::L3);

            install(3, detour);
        }
    }

    thread_ctx.Dr7 = dr_ctl.bits();
    _NtSetContextThread(&set_thread_ctx_sc(), current_thread_handle, &mut thread_ctx);
}

pub unsafe extern "system" fn VectorHandler(pExceptionInfo: *mut EXCEPTION_POINTERS) -> LONG {
    let ex_record = unsafe { *(*pExceptionInfo).ExceptionRecord };

    /* EXCEPTION_SINGLE_STEP */
    if ex_record.ExceptionCode == 0x80000004 {
        let ex_addr = ex_record.ExceptionAddress;
        let ctx_record = unsafe { *(*pExceptionInfo).ContextRecord };

        let dr_addrs = [
            ctx_record.Dr0,
            ctx_record.Dr1,
            ctx_record.Dr2,
            ctx_record.Dr3,
        ];

        let Some(dr_index) = dr_addrs
            .iter()
            .position(|&addr| ex_addr == addr as _)
            .map(|i| i as i32)
        else {
            return 0;
        };

        #[cfg(debug_assertions)]
        println!("matched a detoured function :3");
        let ex_info_ptr = unsafe { (*pExceptionInfo).ContextRecord.as_mut().unwrap() };

        unsafe {
            block_fn(ex_info_ptr);
        };

        ex_info_ptr.EFlags |= 1 << 16;

        // EXCEPTION_CONTINUE_EXECUTION
        return -1;
    }
    // EXCEPTION_CONTINUE_SEARCH
    0
}

#[unsafe(link_section = ".text")]
static RET_INST: [u8; 1] = [0xC3];

pub unsafe fn block_fn(ctx: &mut CONTEXT) {
    ctx.Rip = RET_INST.as_ptr() as u64;
}

pub unsafe fn clobber_ret(ctx: &mut CONTEXT, new_val: u64) {
    ctx.Rax = new_val;
}

pub unsafe fn proceed(ctx: &mut CONTEXT) {
    let curr = ctx.EFlags;
    ctx.EFlags = curr | (1 << 16);
}

bitflags! {
    /// Usage:
    /// ```ignore
    /// let mut ctl = DRCtl::empty();
    /// ctl.insert(DRCtl::L0 | DRCtl::G1); // flag-style access
    /// ctl.set_field(8, 2, 0b11);         // field-style access at bits 16..=17
    /// ```
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct DRCtl: u64 {
        const L0 = 1 << 0;
        const G0 = 1 << 1;
        const L1 = 1 << 2;
        const G1 = 1 << 3;
        const L2 = 1 << 4;
        const G2 = 1 << 5;
        const L3 = 1 << 6;
        const G3 = 1 << 7;

        // avoid truncating unnamed bits
        const _ = !0;
    }
}

impl DRCtl {
    pub fn set_field(&mut self, target_register: u32, count: u32, value: u64) -> u64 {
        let shift = target_register * 2;
        assert!(shift < 64, "field offset out of range");

        // avoid overflowing when `count == 64`
        let mask = 1u64.checked_shl(count).map_or(u64::MAX, |v| v - 1) << shift;

        *self = Self::from_bits_retain((self.bits() & !mask) | ((value << shift) & mask));
        self.bits()
    }
}

pub struct DESCRIPTOR_ENTRY {
    /// Pointer to next linked list element
    pub next: *mut DESCRIPTOR_ENTRY,
    /// Pointer to previous linked list element
    pub prev: *mut DESCRIPTOR_ENTRY,
    /// Address of the breakpoint
    pub address: PVOID,
    /// Index of the hardware debug register (Dr0 - Dr3)
    pub drx: DRX,
    /// ID of the thread in which the breakpoint is installed
    pub thread_id: DWORD,
    /// callback function pointer (i.e. detour function)
    pub callback_fn: PVOID,
    /// flag to indicate node as processed in the VEH function
    pub processed: bool,
}
