#![no_std]

pub mod alloc;
pub mod console;
pub mod hashing;
pub mod winapi;
pub mod winstring;

pub mod prelude {
    pub use crate::alloc;
    pub use crate::winapi;
    pub use crate::{print, println};
}
