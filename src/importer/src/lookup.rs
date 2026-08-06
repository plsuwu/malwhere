use core::ffi::c_void;

use crate::bindings::{FARPROC, HMODULE, PEB};
use crate::peb::FromGSOffset;

pub fn fn_by_hash(_module: *const c_void, _func_hash: u64) -> FARPROC {
    todo!()
}

pub fn module_by_hash(module_hash: u64) -> Option<*const HMODULE> {
    let peb = PEB::from_gs_offset().ok()?;
    peb.walk_modules(module_hash)
}
