use core::fmt::{self, Write};
use core::ptr;

use crate::winapi;

pub(crate) trait RawSink {
    /// Perform one write to a sink.
    ///
    /// Returns the number of bytes that were written to the sink, or `None` on failure.
    fn write_raw(&mut self, buf: &[u8]) -> Option<usize>;
}

/// Writes data from `buf` into `sink` until `buf` is exhausted or `sink` fails.
pub(crate) fn write_all<S: RawSink>(sink: &mut S, mut bytes: &[u8]) -> fmt::Result {
    while !bytes.is_empty() {
        match sink.write_raw(bytes) {
            Some(n) if n > 0 && n <= bytes.len() => bytes = &bytes[n..],
            _ => return Err(fmt::Error),
        }
    }

    Ok(())
}

struct HandleSink(winapi::HANDLE);

impl RawSink for HandleSink {
    /// Write up to 4GiB (i.e. `u32::MAX`) from a buffer into the sink given by `self.0`.
    ///
    /// Buffer content over 4GiB in not truncated when called in a loop (see `write_all` function).
    fn write_raw(&mut self, buf: &[u8]) -> Option<usize> {
        let len = buf.len().min(u32::MAX as usize) as u32;
        let mut written = 0;
        let ok = unsafe {
            winapi::WriteFile(
                self.0,
                buf.as_ptr().cast(),
                len,
                &mut written,
                ptr::null_mut(),
            )
        };

        (ok != 0).then_some(written as usize)
    }
}

pub struct Console(winapi::DWORD);

impl fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let handle = unsafe { winapi::GetStdHandle(self.0) };
        if handle.is_null() || handle == winapi::INVALID_HANDLE_VALUE {
            return Err(fmt::Error);
        }

        write_all(&mut HandleSink(handle), s.as_bytes())
    }
}

impl Console {
    const fn stdout() -> Self {
        Console(winapi::STD_OUTPUT_HANDLE)
    }

    const fn stderr() -> Self {
        Console(winapi::STD_ERROR_HANDLE)
    }

    pub fn print(args: fmt::Arguments) {
        _ = Console::stdout().write_fmt(args);
    }

    pub fn eprint(args: fmt::Arguments) {
        _ = Console::stderr().write_fmt(args);
    }
}

#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::console::Console::print(::core::format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! println {
    () => {
        $crate::console::Console::print(::core::format_args!("\n"))
    };

    ($($arg:tt)*) => {
        $crate::console::Console::print(
            ::core::format_args!(
                "{}\n",
                ::core::format_args!($($arg)*)
            )
        )
    };
}
