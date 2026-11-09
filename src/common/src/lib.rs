#![no_std]

pub mod alloc;
pub mod winapi;
pub mod console;

pub mod prelude {
    pub use crate::alloc;
    pub use crate::winapi;
    pub use crate::console;
}
