//! Global synchronization and function lookup interfaces for exception handling
//!
//! # Usage
//!
//! Generally speaking, this module's components are wrapped with the `HOOK_REGISTRY` reference,
//! which initializes the VEH function with `lazy_static` through a `sync::Once` interface. Each
//! subsequent call to the `.with_lock` method enters a critical section, locking the registry's
//! contents:
//!
//! ```no_run
//! use crate::hook::exception::HOOK_REGISTRY;
//!
//! HOOK_REGISTRY.registry().with_lock(|reg| {
//!
//!     // ...
//!
//! })
//! ```
use crate::hook::hook::Hook;
use crate::hook::registers::DebugRegister;
use lazy_static::lazy_static;

use std::cell::UnsafeCell;
use std::ffi::c_void;
use std::sync::Once;

use windows::Win32::Foundation::EXCEPTION_SINGLE_STEP;
use windows::Win32::System::Diagnostics::Debug::{
    AddVectoredExceptionHandler, RemoveVectoredExceptionHandler, CONTEXT,
    EXCEPTION_CONTINUE_EXECUTION, EXCEPTION_CONTINUE_SEARCH, EXCEPTION_POINTERS,
    PVECTORED_EXCEPTION_HANDLER,
};
use windows::Win32::System::Threading::CRITICAL_SECTION;
use windows::Win32::System::Threading::{
    DeleteCriticalSection, EnterCriticalSection, InitializeCriticalSection, LeaveCriticalSection,
};

/// Global instance of the debug hook map
///
/// Provides a single, globally-accessible controller for the debug register x hooked function
/// address map.
///
/// Initialized lazily on first use.
lazy_static! {
    pub static ref HOOK_REGISTRY: DebugHook = {
        let system = DebugHook::new();
        system.initialize();

        system
    };
}

/// Core struct for register-to-function map management
///
/// Coordinates the hook registry and vectored exception handler to ensure proper initialization
/// and synchronization over the program lifetime.
pub struct DebugHook {
    registry: HookRegistry,
    exception_handler: VectoredExceptionHandler,
}

impl DebugHook {
    pub fn new() -> Self {
        Self {
            registry: HookRegistry::new(),
            exception_handler: VectoredExceptionHandler::new(),
        }
    }

    pub fn initialize(&self) {
        self.exception_handler.initialize();
    }

    /// Intended provider for the hook registry with `HOOK_REGISTRY.registry()`
    pub fn registry(&self) -> &HookRegistry {
        &self.registry
    }
}

/// Provides RAII-style management of Windows critical sections
pub struct WinCriticalSection {
    cs: UnsafeCell<CRITICAL_SECTION>,
}

/// RAII guard for critical section access
pub struct CriticalSectionGuard<'a> {
    cs: &'a WinCriticalSection,
}

impl WinCriticalSection {
    /// Creates and initializes a new Windows critical section
    pub fn new() -> Self {
        let cs = UnsafeCell::new(CRITICAL_SECTION::default());
        unsafe {
            InitializeCriticalSection(cs.get());
        }

        Self { cs }
    }

    /// Enters the critical section to acquire a lock on a resource
    pub fn lock(&self) -> CriticalSectionGuard {
        unsafe {
            EnterCriticalSection(self.cs.get());
        }

        CriticalSectionGuard { cs: self }
    }
}

impl Drop for WinCriticalSection {
    fn drop(&mut self) {
        unsafe {
            DeleteCriticalSection(self.cs.get());
        }
    }
}

impl<'a> Drop for CriticalSectionGuard<'a> {
    fn drop(&mut self) {
        unsafe {
            LeaveCriticalSection(self.cs.cs.get());
        }
    }
}

/// Registry for managing active hooks
///
/// Maintains a mutable, fixed-size, stack-allocated array of hooks mapped to corresponding debug
/// registers, providing synchronized access through a Windows critical section.
pub struct HookRegistry {
    inner: WinCriticalSection,
    registry: UnsafeCell<[(Option<Hook>, *const c_void); 4]>,
}


impl HookRegistry {
    /// Creates a new (empty) hook registry object
    pub fn new() -> Self {
        Self {
            inner: WinCriticalSection::new(),
            registry: UnsafeCell::new([(None, std::ptr::null()); 4]),
        }
    }

    /// Executes a function with exclusive access to the hook registry
    ///
    /// # Arguments
    ///
    /// * `f` - Function to execute with mutable access to the registry
    pub fn with_lock<F, R>(&self, f: F) -> R
    where
        F: FnOnce(&mut [(Option<Hook>, *const c_void); 4]) -> R,
    {
        let mut guard = self.inner.lock();
        let registry = unsafe { &mut *self.registry.get() };
        f(registry)
    }
}

/// Manages custom vectored exception handler functions
pub struct VectoredExceptionHandler {
    handler: UnsafeCell<*mut c_void>,
    init: Once,
}

impl VectoredExceptionHandler {
    pub const fn new() -> Self {
        Self {
            handler: UnsafeCell::new(std::ptr::null_mut()),
            init: Once::new(),
        }
    }

    pub fn initialize(&self) {
        self.init.call_once(|| unsafe {
            let handler: PVECTORED_EXCEPTION_HANDLER =
                std::mem::transmute(vector_handler as *const c_void);
            *self.handler.get() = AddVectoredExceptionHandler(1, handler);
        })
    }
}

impl Drop for VectoredExceptionHandler {
    fn drop(&mut self) {
        unsafe {
            let handler = *self.handler.get();
            if !handler.is_null() {
                RemoveVectoredExceptionHandler(handler);
            }
        }
    }
}

unsafe impl Send for WinCriticalSection {}
unsafe impl Sync for WinCriticalSection {}

unsafe impl Send for HookRegistry {}
unsafe impl Sync for HookRegistry {}

unsafe impl Send for VectoredExceptionHandler {}
unsafe impl Sync for VectoredExceptionHandler {}

/// Exception handler callback
///
/// Called by Windows when a debug exception occurs (this handler function is invoked by the OS).
pub unsafe extern "system" fn vector_handler(raw_exception: *mut EXCEPTION_POINTERS) -> i32 {
    let exception_info = &*raw_exception;

    // if the exception is not `EXCEPTION_SINGLE_STEP` then we defer its handling to a different
    // function
    if (*exception_info.ExceptionRecord).ExceptionCode != EXCEPTION_SINGLE_STEP {
        return EXCEPTION_CONTINUE_SEARCH;
    }

    let exception_addr = (*exception_info.ExceptionRecord).ExceptionAddress as u64;
    let context = &*exception_info.ContextRecord;

    // determine the debug register by comparing the address in each `ThreadContext` debug register
    // to the address associated with the exception
    let debug_registers = [context.Dr0, context.Dr1, context.Dr2, context.Dr3];
    let Some(dr_idx) = debug_registers
        .iter()
        .position(|&addr| addr == exception_addr)
        .map(|i| i as i32)
    else {
        return EXCEPTION_CONTINUE_SEARCH;
    };

    HOOK_REGISTRY.registry().with_lock(|reg| {
        let (hook, func) = &mut reg[dr_idx as usize];
        let Some(mut hook) = hook.take() else {
            return EXCEPTION_CONTINUE_SEARCH;
        };

        let drx = DebugRegister::try_from(dr_idx).unwrap();
        hook.disable_breakpoint(drx); // disable breakpoint

        let callback: fn(&mut CONTEXT) -> usize = std::mem::transmute(*func);
        callback(exception_info.ContextRecord.as_mut().unwrap());

        hook.enable_breakpoint(drx); // re-enable breakpoint
        EXCEPTION_CONTINUE_EXECUTION // resume regular program flow
    })
}
