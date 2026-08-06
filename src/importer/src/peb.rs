extern crate alloc;

use utilities::hash_wstr;
use utilities::{MemoryError, string::utf16_from_ptr};

use crate::bindings::{HMODULE, LDR_DATA_TABLE_ENTRY, PEB};

/// Retrieves a pointer relative to the GS register at a given offset.
///
/// # Safety
///
/// Uses inline assembly to read and return register data; this function cannot make any guarantees that the
/// given offset is valid, so the callee is responsible for ensuring that it points to a valid structure.
#[inline]
#[cfg(all(target_pointer_width = "64", target_arch = "x86_64"))]
pub unsafe fn __readgsqword(offset: u64) -> u64 {
    let res;
    unsafe {
        core::arch::asm!(
            "mov {}, qword ptr gs:[{:e}]",
            out(reg) res,
            in(reg) offset,
            options(nostack, readonly, preserves_flags)
        );
    }

    res
}

pub trait FromGSOffset
where
    Self: core::marker::Sized,
{
    fn from_gs_offset() -> Result<Self, MemoryError>;
}

impl FromGSOffset for PEB {
    fn from_gs_offset() -> Result<Self, MemoryError> {
        let ptr = unsafe { __readgsqword(0x60) } as *const PEB;

        Ok(unsafe { *ptr })
    }
}

impl PEB {
    pub fn walk_modules(&self, module_hash: u64) -> Option<*const HMODULE> {
        let ldr_data = unsafe { *self.Ldr };

        let p_module_head = ldr_data.InMemoryOrderModuleList;
        let mut p_current_module = p_module_head.Flink;
        let mut p_data_table_entry = p_current_module as *mut LDR_DATA_TABLE_ENTRY;

        loop {
            let unicode_str = unsafe { (*p_data_table_entry).FullDllName };
            let dll_name = utf16_from_ptr(unicode_str.Buffer);

            if module_hash == hash_wstr!(&dll_name) {
                let handle = unsafe { *p_data_table_entry }.Reserved2[0];
                return Some(&handle);
            }

            if p_current_module.addr() != p_module_head.Blink.addr() {
                p_data_table_entry =
                    unsafe { *p_current_module }.Flink as *mut LDR_DATA_TABLE_ENTRY;
                p_current_module = unsafe { *p_current_module }.Flink;
            } else {
                break;
            }
        }

        None
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn peb_ptr_resolves() {
        let ptr = (Into::<*const c_void>::into(&Block::PEB)) as *mut PEB;
        let peb: PEB = unsafe { *ptr };

        // probably always 0 during tests
        assert!(peb.BeingDebugged >= 0 && peb.BeingDebugged <= 1);
    }

    #[test]
    fn get_peb_resolved() {
        let peb_res = get_peb();
        assert!(peb_res.is_ok());

        let peb = peb_res.unwrap();
        assert!(peb.BeingDebugged == 0 || peb.BeingDebugged == 1);
    }

    #[test]
    fn teb_self_pointer_is_nonzero() {
        let teb = unsafe { __readgsqword(0x30) };
        assert_ne!(teb, 0, "TEB self-pointer should not be null");
    }

    #[test]
    fn teb_self_pointer_matches_api() {
        unsafe extern "system" {
            fn NtCurrentTeb() -> *mut core::ffi::c_void;
        }
        let via_asm = unsafe { __readgsqword(0x30) };
        let via_api = unsafe { NtCurrentTeb() } as u64;
        assert_eq!(via_asm, via_api);
    }

    #[test]
    fn stack_base_is_above_stack_limit() {
        // - `gs:[0x08]` is `StackBase`
        // - `gs:[0x10]` is `StackLimit`
        let base = unsafe { __readgsqword(0x08) };
        let limit = unsafe { __readgsqword(0x10) };
        assert!(base > limit);
    }

    #[test]
    fn current_stack_in_teb_bounds() {
        // a local variable address should sit between `StackLimit` and `StackBase`
        let local = 0u8;
        let addr = (&local as *const u8).addr() as u64;
        let base = unsafe { __readgsqword(0x08) };
        let limit = unsafe { __readgsqword(0x10) };
        assert!(addr >= limit && addr < base);
    }
}
