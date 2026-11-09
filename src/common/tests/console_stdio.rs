use std::ptr;

use common::winapi::{CloseHandle, GetStdHandle, SetStdHandle};
use common::winapi::{CreatePipe, ReadFile};
use common::winapi::{HANDLE, STD_OUTPUT_HANDLE};

/// Helper: reads captured data back from a `HANDLE` into a `Vec`.
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

/// Wrapper to print the result of an assertion to stdout as part of test runner to indicate when
/// tests were actually run and were successful (despite the test runner indicating otherwise).
fn check(name: &str, got: Vec<u8>, want: &[u8]) {
    assert_eq!(got, want, "{name}");
    println!("(no harness): test {name} -> ok");
}

/// Capture the result of a closure `f` in an anonymous Windows pipe
fn capture(which: u32, f: impl FnOnce()) -> Vec<u8> {
    unsafe {
        let (mut r, mut w): (HANDLE, HANDLE) = (ptr::null_mut(), ptr::null_mut());
        assert_ne!(CreatePipe(&mut r, &mut w, ptr::null_mut(), 1 << 16), 0);

        let original = GetStdHandle(which);
        SetStdHandle(which, w);

        f();

        SetStdHandle(which, original);
        CloseHandle(w);

        read_to_end(r)
    }
}

fn main() {
    // assertions
    check(
        "print_macro",
        capture(STD_OUTPUT_HANDLE, || common::print!("a{}c", 'b')),
        b"abc",
    );
    check(
        "println_empty",
        capture(STD_OUTPUT_HANDLE, || common::println!()),
        b"\n",
    );
    check(
        "println_args",
        capture(STD_OUTPUT_HANDLE, || common::println!("x = {}", 5)),
        b"x = 5\n",
    );
}
