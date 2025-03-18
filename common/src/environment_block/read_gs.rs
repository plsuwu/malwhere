use core::arch::asm;

use super::types::PROCESS_ENVIRONMENT_BLOCK as PEB;
use windows::Win32::System::Threading::TEB;
// use windows::Win32::System::Threading::PEB;


/// Read an offset from the GS register
///
/// Used mostly for PEB retrieval
#[inline]
#[cfg(target_arch = "x86_64")]
pub fn __readgsqword(offset: u64) -> u64 {
    let mut result: u64;
    unsafe {

        asm!(
            "mov {}, gs:[{:e}]",
            out(reg) result,
            in(reg) offset,
            options(nostack, pure, readonly),
        );
    }

    result
}

pub trait GetBlock {
    fn get_ptr() -> *const Self;
    fn get() -> Self;
}

impl GetBlock for TEB {
    fn get_ptr() -> *const Self {
        __readgsqword(0x30) as *const TEB
    }

    fn get() -> Self {
        unsafe { *Self::get_ptr() }
    }
}

impl GetBlock for PEB {
    fn get_ptr() -> *const Self {
        __readgsqword(0x60) as *const PEB
    }

    fn get() -> Self {
        unsafe { *Self::get_ptr() }
    }
}
