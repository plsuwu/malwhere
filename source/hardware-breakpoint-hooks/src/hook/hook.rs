//! Main function hook implementation interface
//!
//! This module provides the core Hook type to manage hardware breakpoint function hooks using
//! x64 debug registers. These hooks work by configuring physical CPU debug registers to generate
//! an exception when the `$rip` register hits a specified memory address, which can be used as
//! part of a Windows exception handling routine to divert execution to a different address.
//!
//! NOTE: Each thread by nature has its own thread context via the `CONTEXT` structure due to the
//! nature of multithreading.
use crate::hook::exception::HOOK_REGISTRY;
use crate::hook::registers::{DebugControlRegister, DebugRegister};
use std::ffi::c_void;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Diagnostics::Debug::{
    GetThreadContext, SetThreadContext, CONTEXT, CONTEXT_DEBUG_REGISTERS_AMD64,
};

/// Helper function to return a `HANDLE` to the current thread via a pseudo-handle
fn current_thread() -> HANDLE {
    HANDLE(-2 as _)
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct Hook {
    pub context: CONTEXT,
    pub control: DebugControlRegister,
    pub target: *const c_void,
    pub detour: *const c_void,
}

impl Hook {
    /// Creates a new hook for the specified target and detour functions
    ///
    /// Initializes hook parameters without installing it - The hook must explicitly call its
    /// `install()` method to install and enable a breakpoint at a given address.
    ///
    /// # Arguments
    ///
    /// * `detour_fn` - `*const c_void` pointer to a function that should be called when the
    ///     breakpoint is triggered. Note that this function should be of the type
    ///     `unsafe extern "system" fn func_name(&mut CONTEXT)` so that it can use the `CONTEXT`
    ///     struct.
    /// * `target_fn` - `*const c_void` pointer to the function to hook
    ///
    /// # Returns
    ///
    /// Returns a `Result` with the new `Hook` instance if successful, otherwise a general
    /// `anyhow::Error` describing the error encountered.
    ///
    /// # Usage
    ///
    ///
    /// ```no_run
    /// // example function that increments an integer by `1`
    /// fn increment_int(a: usize) -> usize {
    ///     a + 1
    /// }
    ///
    /// fn example_detour(ctx: &mut CONTEXT) {
    ///
    ///     // the detour function can implement the `crate::context::*` functions to read and
    ///     // alter the hooked function call arguments (alternatively, `get_param!`/`set_param!`).
    ///
    ///     let arg_a = get_param!(ctx, 0); // read the first arg from `ctx`
    ///     assert_eq!(arg_a,
    ///
    ///     // `$rip` continues execution from the original function unless `block_execution`
    ///     // is called:
    ///     block_execution(ctx);
    ///
    ///     // e.g set hooked function's return to `99`
    ///     clobber_return(ctx, 99);
    /// }
    ///
    ///
    /// fn main() {
    ///     let incremented = increment_a(1);
    ///     assert_eq!(incremented, 2);
    ///
    ///     // create and apply hook
    ///     let hook = Hook::new(
    ///         example_detour as *const c_void,
    ///         increment_int as *const c_void,
    ///     ).unwrap();
    ///
    ///     hook.install(Drx::Dr0); // use debug register 0 (`CONTEXT.Dr0`)
    ///     let incremented_hooked = increment_a(1);
    ///
    ///     assert_eq!(incremented_hooked, 99);
    /// }
    /// ```
    pub fn new(detour_fn: *const c_void, target_fn: *const c_void) -> anyhow::Result<Self> {
        let dr7 = DebugControlRegister::new();
        let thread_ctx = Self::get_ctx()?;

        Ok(Self {
            context: thread_ctx,
            control: dr7,
            detour: detour_fn,
            target: target_fn,
        })
    }

    /// Populates the current thread's `CONTEXT` struct which is used as a baseline when installing
    /// hooks
    ///
    /// > NOTE: Implementation here is not quite correct and requires some massaging to implement
    /// > correctly. Uses a bit of a hacky workaround for now (see `install` method) and should be
    /// > a reasonably straightforward fix.
    ///
    /// # Returns
    ///
    /// `Result` containing the populated `CONTEXT` struct on success, otherwise a general `anyhow`
    /// Error describing the issue encountered.
    pub fn get_ctx() -> anyhow::Result<CONTEXT> {
        let mut thread_ctx = CONTEXT {
            ContextFlags: CONTEXT_DEBUG_REGISTERS_AMD64,
            ..Default::default()
        };

        unsafe {
            GetThreadContext(current_thread(), &mut thread_ctx)?;
        }

        Ok(thread_ctx)
    }

    /// Sets a specified address into a specified debug register
    ///
    /// # Arguments
    ///
    /// * `drx` - The debug register to configure (`Dr0` to `Dr3`)
    /// * `address` - The address to set a breakpoint at
    pub fn set_drx(&mut self, drx: DebugRegister, address: u64) {
        match drx {
            DebugRegister::Dr0 => self.context.Dr0 = address,
            DebugRegister::Dr1 => self.context.Dr1 = address,
            DebugRegister::Dr2 => self.context.Dr2 = address,
            DebugRegister::Dr3 => self.context.Dr3 = address,
        }
    }

    /// Installs the hook's address into the specified debug register
    ///
    /// # Arguments
    ///
    /// * `drx` - The debug register to use for this hook
    ///
    /// # Returns
    ///
    /// `Ok(())` if the hook installation was successful, otherwise a general `anyhow::Error`
    pub fn install(&mut self, drx: DebugRegister) -> anyhow::Result<()> {

        // TODO: Fix this implementation:
        //  ----------------------------
        //  this is a bit of a hack for now as each new hook overwrites the `CONTEXT` with empty
        //  debug registers when the `Hook::new` method calls `get_ctx()`. Converting this to a 
        //  lib so I'll fix it at some point (surely) but for now here we are

        HOOK_REGISTRY.registry().with_lock(|reg| {
            reg[drx as usize] = (Some(*self), self.detour);

            for (i, (hook, _)) in reg.iter().enumerate() {
                if hook.is_some() {
                    let mut h = hook.unwrap();
                    self.set_drx(DebugRegister::try_from(i as i32).unwrap(), h.target as u64);
                    self.enable_breakpoint(DebugRegister::try_from(i as i32).unwrap());
                }
            }
        });

        self.context.Dr7 = self.enable_breakpoint(drx);
        unsafe {
            SetThreadContext(current_thread(), &self.context)?;
        }

        Ok(())
    }

    /// Removes the hook from the specified debug register
    ///
    /// This disables the breakpoint and also clears the specified debug register, clearing the
    /// hook from the machine's hardware.
    ///
    /// # Returns
    ///
    /// `Ok(())` if the hook removal was successful, otherwise a general `anyhow::Error`
    pub fn remove(&mut self, drx: DebugRegister) -> anyhow::Result<()> {
        self.set_drx(drx, 0u64);
        self.context.Dr7 = self.disable_breakpoint(drx);
        unsafe {
            SetThreadContext(current_thread(), &self.context)?;
        }

        Ok(())
    }

    /// Enables a breakpoint for a specified debug register
    ///
    /// Configures the debug control register `Dr7` to set the global control bit for a debug
    /// register to `1`, effectively enabling that breakpoint.
    pub fn enable_breakpoint(&mut self, drx: DebugRegister) -> u64 {
        self.control.set(drx as _, 1, 1)
    }

    /// Disables a breakpoint for a specified debug register
    ///
    /// Configures the debug control register `Dr7` to set the global control bit for a debug
    /// register to `0`, effectively disabling that breakpoint.
    ///
    /// NOTE: Does **not** clear the address from the debug register `Drx`; this method is intended
    /// as a way to temporarily toggle off a breakpoint without completely uninstalling the hook.
    pub fn disable_breakpoint(&mut self, drx: DebugRegister) -> u64 {
        self.control.set(drx as _, 1, 0)
    }
}
