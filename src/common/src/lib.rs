#![no_std]

pub mod alloc;
pub mod console;
pub mod hashing;
pub mod winapi;
pub mod winstring;
pub mod rand;

pub mod prelude {
    pub use crate::hashing::DEFAULT_KEY;
    pub use crate::winapi;
    pub use crate::{eprint, eprintln, print, println};
    pub use crate::{rt_widehash, widehash};
}
