use core::ffi::c_void;
use core::fmt::{self, Write};

use crate::bindings::{GetStdHandle, STD_ERROR_HANDLE, STD_OUTPUT_HANDLE, WriteFile};

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::console::_print(::core::format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! println {
    () => {
        $crate::console::_print(::core::format_args!("\n"))
    };

    ($($arg:tt)*) => {
        $crate::console::_print(::core::format_args!("{}\n", ::core::format_args!($($arg)*)))
    };
}

pub struct ConWriter {
    handle: u32,
}

impl ConWriter {
    pub const fn stdout() -> Self {
        ConWriter {
            handle: STD_OUTPUT_HANDLE,
        }
    }

    pub const fn stderr() -> Self {
        ConWriter {
            handle: STD_ERROR_HANDLE,
        }
    }
}

impl Write for ConWriter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let bytes = s.as_bytes();
        let mut written: u32 = 0;

        let h = unsafe { GetStdHandle(self.handle) };
        let mut offset = 0usize;

        while offset < bytes.len() {
            let ok = unsafe {
                WriteFile(
                    h,
                    bytes[offset..].as_ptr() as *const c_void,
                    (bytes.len() - offset) as u32,
                    &mut written as *mut u32,
                    core::ptr::null_mut(),
                )
            };

            if ok == 0 || written == 0 {
                return Err(fmt::Error);
            }

            offset += written as usize;
        }

        Ok(())
    }
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    let _ = ConWriter::stdout().write_fmt(args);
}

#[doc(hidden)]
pub fn _eprint(args: fmt::Arguments) {
    let _ = ConWriter::stderr().write_fmt(args);
}
