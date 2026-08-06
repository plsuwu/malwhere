#![no_std]

pub type BOOL = core::ffi::c_int;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryError {
    NullPointer,
    InvalidAlignment,
    LengthOverflow,
}

// pub mod memory;
pub mod bindings;
pub mod hashing;
pub mod string;
pub mod alloc;
pub mod console;