#![allow(clippy::not_unsafe_ptr_arg_deref)]

extern crate alloc;

use alloc::vec::Vec;

pub const MAX_PATH: usize = 260;

pub fn utf16_ptr_len(ptr: *mut u16) -> usize {
    let mut len = 0usize;

    // SAFETY: assumes pointer is non-null; callee should ensure
    // pointer is a valid u16 array
    while unsafe { *ptr.add(len) } != 0 {
        len += 1;
    }

    len
}

pub fn utf16_from_ptr(ptr: *mut u16) -> Vec<u16> {
    let mut res = Vec::new();
    let len = utf16_ptr_len(ptr);
    let slice = unsafe { core::slice::from_raw_parts(ptr, len) };
    res.extend_from_slice(slice);
    res
}

pub fn from_utf16(units: &[u16], len: usize, out: &mut [u8]) {
    let mut i = 0; // unit index
    let mut o = 0; // byte index

    while i < len {
        let u = units[i] as u32;
        let cp = if (0xD800..=0xDBFF).contains(&u) {
            let hi = u;
            let lo = units[i + 1] as u32;
            i += 2;
            0x1_0000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
        } else {
            i += 1;
            u
        };

        if cp < 0x80 {
            out[o] = cp as u8;
            o += 1;
        } else if cp < 0x800 {
            out[o] = (0xC0 | (cp >> 6)) as u8;
            out[o + 1] = (0x80 | (cp & 0x3F)) as u8;
            o += 2;
        } else if cp < 0x1_0000 {
            out[o] = (0xE0 | (cp >> 12)) as u8;
            out[o + 1] = (0x80 | ((cp >> 6) & 0x3F)) as u8;
            out[o + 2] = (0x80 | (cp & 0x3F)) as u8;
            o += 3;
        } else {
            out[o] = (0xF0 | (cp >> 18)) as u8;
            out[o + 1] = (0x80 | ((cp >> 12) & 0x3F)) as u8;
            out[o + 2] = (0x80 | ((cp >> 6) & 0x3F)) as u8;
            out[o + 3] = (0x80 | (cp & 0x3F)) as u8;
            o += 4;
        }
    }
}

pub const fn utf8_len(units: &[u16]) -> usize {
    let mut i = 0;
    let mut bytes = 0;
    while i < units.len() {
        let u = units[i] as u32;

        let cp = if u >= 0xD800 && u <= 0xDBFF {
            let hi = u;
            let lo = units[i + 1] as u32;
            i += 2;
            0x1_0000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
        } else {
            i += 1;
            u
        };

        bytes += if cp < 0x80 {
            1
        } else if cp < 0x800 {
            2
        } else if cp < 0x1_0000 {
            3
        } else {
            4
        };
    }

    bytes
}

/// Calculates the length of an 8-bit/UTF-8 string as a wide-encoded UTF-16 wide string.
pub const fn utf16_len(s: &str) -> usize {
    let b = s.as_bytes();
    let mut i = 0;
    let mut units = 0;

    while i < b.len() {
        let c = b[i];
        // Unicode "astral plane" characters (> 0xFFFF) need 21 bits for correct representation; Windows
        // uses UTF-16, which requires us to represent this with two-code units/"surrogate pairs".
        let (cp_len, is_astral) = if c < 0x80 {
            (1, false)
        } else if c < 0xE0 {
            (2, false)
        } else if c < 0xF0 {
            (3, false)
        } else {
            (4, true)
        };

        units += if is_astral { 2 } else { 1 };
        i += cp_len;
    }

    units
}

pub const fn to_utf16<const N: usize>(s: &str) -> [u16; N] {
    let b = s.as_bytes();
    let mut out = [0u16; N];
    let mut i = 0;
    let mut o = 0;

    while i < b.len() {
        let c0 = b[i] as u32;
        let (cp, len) = if c0 < 0x80 {
            (c0, 1)
        } else if c0 < 0xE0 {
            (((c0 & 0x1F) << 6) | (b[i + 1] as u32 & 0x3F), 2)
        } else if c0 < 0xF0 {
            (
                ((c0 & 0x0f) << 12) | ((b[i + 1] as u32 & 0x3F) << 6) | (b[i + 2] as u32 & 0x3F),
                3,
            )
        } else {
            (
                ((c0 & 0x07) << 18)
                    | ((b[i + 1] as u32 & 0x3F) << 12)
                    | ((b[i + 2] as u32 & 0x3F) << 6)
                    | (b[i + 3] as u32 & 0x3F),
                4,
            )
        };

        if cp < 0x1_0000 {
            out[o] = cp as u16;
            o += 1;
        } else {
            let v = cp - 0x1_0000;
            out[o] = (0xD800 + (v >> 10)) as u16;
            out[o + 1] = (0xDC00 + (v & 0x3FF)) as u16;
            o += 2;
        }

        i += len;
    }

    out
}

#[cfg(test)]
mod test {
    extern crate alloc;

    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn to_utf16_matches_stdlib() {
        const S: &str = "café 日本語 😀";
        const N: usize = utf16_len(S);
        let ours = to_utf16::<N>(S);
        let std: Vec<u16> = S.encode_utf16().collect();

        assert_eq!(&ours[..], std.as_slice());
    }

    #[test]
    fn surrogate_pair_encoded() {
        const S: &str = "😀";
        const N: usize = utf16_len(S);
        assert_eq!(N, 2);

        let u = to_utf16::<N>(S);
        assert!((0xD800..=0xDBFF).contains(&u[0]), "high surrogate");
        assert!((0xDC00..=0xDFFF).contains(&u[1]), "low surrogate");
    }

    #[test]
    fn utf16_len_matches_std() {
        for s in ["", "a", "hello", "café", "naïve", "日本語", "emoji 😀 test"] {
            let expected = s.encode_utf16().count();
            assert_eq!(
                crate::string::utf16_len(s),
                expected,
                "len mismatch for {s:?}"
            );
        }
    }

    #[test]
    fn from_utf16_roundtrip() {
        for s in ["", "hello", "café", "日本語", "ab123l_%dfj 😀 中 x"] {
            let units: alloc::vec::Vec<u16> = s.encode_utf16().collect();
            let mut buf = [0u8; 128];
        }
    }

    #[test]
    fn from_utf16_stops_at_null() {
        let units = [b'h' as u16, b'i' as u16, 0, b'x' as u16];
        let mut buf = [0u8; 16];
    }

    #[test]
    fn from_utf16_wobf_roundtrip() {
        // "aGa198mo *_ 完了 ✓"
        let wide = [
            0x0061, 0x0047, 0x0061, 0x0031, 0x0039, 0x0038, 0x006d, 0x006f, 0x0020, 0x002a, 0x005f,
            0x0020, 0x5b8c, 0x4e86, 0x0020, 0x2713, 0x0000,
        ];

        let mut buf = [0u8; 64];
    }
}
