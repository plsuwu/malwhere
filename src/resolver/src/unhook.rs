use core::ffi::c_void;
use core::slice::from_raw_parts;

pub const JMP_OPCODE: [u8; 1] = [0xE9];
pub const SYSCALL_OPCODES: [u8; 4] = [0x4C, 0x8B, 0xD1, 0xB8];
pub const OFFSET_RANGE: usize = 0xFF;

/// Retrieve the SSN if a given window's bytes match expected syscall setup
pub fn check_opcodes(opcodes: &[u8]) -> Option<u32> {
    if opcodes.starts_with(&SYSCALL_OPCODES) && opcodes.ends_with(&[0x00, 0x00]) {
        let high = opcodes[5] as u32;
        let low = opcodes[4] as u32;

        return Some((high << 8) | low);
    }

    None
}

/// Resolve the `rel32` displacement target of a hook at `hook_off` inside `window`, i.e.
/// the address of the original (pre-hook) code
///
/// Only handles `0xE9` hot-patch hooks at byte 0 (`E9 rel32`) and byte 3 (`4C 8B D1 E9 rel32`),
/// and returns None otherwise
pub fn jmp_target(window: &[u8], hook_off: usize) -> Option<usize> {
    let head = window.get(hook_off..hook_off + 8)?;
    let (disp_off, end_off) = if head.starts_with(&JMP_OPCODE) {
        (1, 5)
    } else if head.starts_with(&SYSCALL_OPCODES[..3]) && head[3] == JMP_OPCODE[0] {
        (4, 8)
    } else {
        return None;
    };

    let disp = window
        .get(hook_off + disp_off..hook_off + disp_off + 4)?
        .try_into()
        .ok()
        .map(i32::from_le_bytes)?;
    let target = (hook_off + end_off).checked_add_signed(disp as isize)?;
    window.get(target..target + 8)?;

    Some(target)
}

/// Resolve the `rel32` displacement target of a hook at `addr`
pub unsafe fn raw_jmp_target(addr: *const c_void) -> Option<*const c_void> {
    let window = unsafe {
        from_raw_parts(
            (addr as *const u8).sub(OFFSET_RANGE - 1),
            OFFSET_RANGE * 2 + 8,
        )
    };
    jmp_target(window, OFFSET_RANGE - 1)
        .map(|off| unsafe { window.as_ptr().add(off) as *const c_void })
}

/// Scan memory window `window` (containing at least `OFFSET_RANGE` bytes on each side of a `0xE9`
/// hook at offset `hook_off`) for an unhooked syscall stub
pub fn scan_jmp_stub(window: &[u8], hook_off: usize) -> Option<u32> {
    for idx in 0..OFFSET_RANGE {
        for off in [hook_off + idx, hook_off - idx] {
            if let Some(ssn) = window.get(off..off + 8).and_then(check_opcodes) {
                return Some(ssn);
            }
        }
    }

    None
}
