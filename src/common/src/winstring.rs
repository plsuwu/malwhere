pub const fn str_utf16_len(s: &str) -> usize {
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

pub const fn str_to_utf16<const N: usize>(s: &str) -> [u16; N] {
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
    extern crate std;

    use super::*;

    #[test]
    fn to_utf16_matches_stdlib() {
        const S: &str = "café 日本語 😀";
        const N: usize = str_utf16_len(S);
        let hand_roll = str_to_utf16::<N>(S);

        let std: std::vec::Vec<u16> = S.encode_utf16().collect();

        assert_eq!(&hand_roll[..], std.as_slice());
    }

    #[test]
    fn surrogate_pair_encoded() {
        const S: &str = "😀";
        const N: usize = str_utf16_len(S);

        assert_eq!(N, 2);

        let u = str_to_utf16::<N>(S);

        assert!((0xD800..=0xDBFF).contains(&u[0]), "high surrogate");
        assert!((0xDC00..=0xDFFF).contains(&u[1]), "low surrogate");
    }
}
