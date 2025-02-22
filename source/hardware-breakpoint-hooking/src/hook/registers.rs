//! Debug register control
//!
//! Provides abstractions for x64 hardware debug register manipulation through the Windows
//! thread context API.

use std::ops::Mul;

/// Enum representing the four available hardware debug registers on x86_64 processors
#[derive(Debug, Clone, Copy)]
pub enum DebugRegister {
    Dr0 = 0,
    Dr1 = 1,
    Dr2 = 2,
    Dr3 = 3,
}

impl DebugRegister {
    /// Creates a `DebugRegister` given a numeric index.
    ///
    /// Useful when determining which debug register generated a debug exception.
    ///
    /// # Arguments
    ///
    /// * `value` - An i32 in the range 0 to 3 (inclusive) representing a debug register index
    pub fn try_from(value: i32) -> Result<Self, &'static str> {
        match value {
            0 => Ok(Self::Dr0),
            1 => Ok(Self::Dr1),
            2 => Ok(Self::Dr2),
            3 => Ok(Self::Dr3),
            _ => Err("Invalid debug register."),
        }
    }
}

/// `Mul` trait implementation for `DebugRegister` types with `u64` types
impl Mul<u64> for DebugRegister {
    type Output = u64;

    fn mul(self, rhs: u64) -> Self::Output {
        (self as u64) * rhs
    }
}

/// Standard conversion trait implementation to create a `DebugRegister` value from an `i32`
/// (though this could be any arbitrary integer type)
impl TryFrom<i32> for DebugRegister {
    type Error = &'static str;

    fn try_from(val: i32) -> Result<Self, Self::Error> {
        DebugRegister::try_from(val)
    }
}

/// Represents the `Dr7` control register bitfield used to enable and disable a given debug
/// register.
///
/// See [this Wikipedia article](https://en.wikipedia.org/wiki/X86_debug_register#DR7_-_Debug_control)
/// for details on each control bit; the implementation below is only concerned with `G0` through
/// `G3` ('Global enable for breakpoint 0-3').
#[derive(Debug, Clone, Copy)]
pub struct DebugControlRegister {
    pub bits: u64,
}

/// Creates a new debug control register with all bits initialized at `0`.
///
/// In the initial state, all debug registers are disabled and any breakpoint addresses will not
/// trigger an exception.
impl DebugControlRegister {
    pub fn new() -> Self {
        Self { bits: 0u64 }
    }

    /// Sets control bits for a specified debug register in a global context in `Dr7`.
    ///
    /// # Arguments
    ///
    /// * `target_register` - The index for a debug register (`Dr0`/`Dr1`/`Dr2`/`Dr3`)
    /// * `count` - The number of bits to modify
    /// * `new_value` - The value to set; valid values are `0` (disabled) or `1` (enabled)
    ///
    /// # Returns
    ///
    /// The `Dr7` register in its updated state
    pub fn set(&mut self, target_register: u32, count: u32, new_value: u64) -> u64 {
        let start_pos = target_register * 2;
        let mask: u64 = ((1u32 << count) - 1u32) as u64;
        self.bits = (self.bits & !(mask << start_pos)) | (new_value << start_pos);

        self.bits
    }
}
