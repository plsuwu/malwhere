#![no_std]

pub mod alloc;
pub mod winapi;

pub mod prelude {
    pub use crate::alloc;
    pub use crate::winapi;
}
