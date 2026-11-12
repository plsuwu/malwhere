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

#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => {
        $crate::console::Console::eprint(::core::format_args!($($arg)*))
    };
}

#[macro_export]
macro_rules! eprintln {
    () => {
        $crate::console::Console::eprint(::core::format_args!("\n"))
    };

    ($($arg:tt)*) => {
        $crate::console::Console::eprint(
            ::core::format_args!(
                "{}\n",
                ::core::format_args!($($arg)*)
            )
        )
    };
}

#[cfg(test)]
mod test {
    #![allow(dead_code, unused_imports)]
    extern crate std;

    use std::vec::Vec;

    use super::*;
    use crate::winapi::HANDLE;
    use crate::winapi::{CloseHandle, CreatePipe, ReadFile};

    /// Helper: construct and return read/write ends of an anonymous pipe.
    ///
    /// Returns `(HANDLE, HANDLE)`, which corresponds to `(Reader, Writer)`.
    fn pipe() -> (HANDLE, HANDLE) {
        let (mut r, mut w) = (ptr::null_mut(), ptr::null_mut());
        assert_ne!(
            unsafe { CreatePipe(&mut r, &mut w, ptr::null_mut(), 1 << 20) },
            0
        );

        (r, w)
    }

    /// Helper: read captured data back from a `HANDLE` into a `Vec`.
    ///
    /// Assumes `HANDLE` will yield valid UTF-8 when read back with `ReadFile`.
    fn read_to_end(h: HANDLE) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            let mut n = 0;
            let ok = unsafe {
                ReadFile(
                    h,
                    buf.as_mut_ptr().cast(),
                    buf.len() as u32,
                    &mut n,
                    ptr::null_mut(),
                )
            };
            if ok == 0 || n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n as usize]);
        }
        unsafe { CloseHandle(h) };
        out
    }

    struct MockSink {
        script: Vec<Option<usize>>,
        out: Vec<u8>,
        calls: usize,
    }

    impl MockSink {
        fn new(script: &[Option<usize>]) -> Self {
            Self {
                script: script.to_vec(),
                out: Vec::new(),
                calls: 0,
            }
        }
    }

    impl RawSink for MockSink {
        fn write_raw(&mut self, buf: &[u8]) -> Option<usize> {
            let step = self
                .script
                .get(self.calls)
                .copied()
                .unwrap_or(Some(usize::MAX));

            self.calls += 1;
            let n = step?.min(buf.len());
            self.out.extend_from_slice(&buf[..n]);

            Some(n)
        }
    }

    #[test]
    fn handle_sink_writes_bytes() {
        let (r, w) = pipe();
        write_all(&mut HandleSink(w), "Ʃʬ".as_bytes()).unwrap();
        unsafe { CloseHandle(w) };
        assert_eq!(read_to_end(r), "Ʃʬ".as_bytes());
    }

    #[test]
    fn handle_sink_fails_on_closed_pipe() {
        let (r, w) = pipe();
        unsafe { CloseHandle(r) };
        assert!(write_all(&mut HandleSink(w), b"abc").is_err());
        unsafe { CloseHandle(w) };
    }

    #[test]
    fn writes_all_content_in_single_call() {
        let mut s = MockSink::new(&[]);
        assert!(write_all(&mut s, b"hello").is_ok());
        assert_eq!(s.out, b"hello");
        assert_eq!(s.calls, 1);
    }

    #[test]
    fn handles_partial_writes() {
        let mut s = MockSink::new(&[Some(2), Some(1), Some(10)]);
        assert!(write_all(&mut s, b"hello").is_ok());
        assert_eq!(s.out, b"hello");
        assert_eq!(s.calls, 3);
    }

    #[test]
    fn zero_byte_writes_return_error() {
        let mut s = MockSink::new(&[Some(2), Some(0)]);
        assert!(write_all(&mut s, b"hello").is_err());
        assert_eq!(s.out, b"he");
    }

    #[test]
    fn propagates_failure() {
        let mut s = MockSink::new(&[None]);
        assert!(write_all(&mut s, b"should err").is_err());
    }

    #[test]
    fn empty_string_does_not_call_writer() {
        let mut s = MockSink::new(&[]);
        assert!(write_all(&mut s, b"").is_ok());
        assert_eq!(s.calls, 0);
    }

    #[test]
    fn invalid_sink_bytes_are_rejects() {
        struct LiesMalicious;
        impl RawSink for LiesMalicious {
            fn write_raw(&mut self, buf: &[u8]) -> Option<usize> {
                Some(buf.len() + 1)
            }
        }
        assert!(write_all(&mut LiesMalicious, b"erroneous").is_err());
    }
}
