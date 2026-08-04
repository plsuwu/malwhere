//! Compile-time hashing utilities
//!
//! The hashing macro intends to take a UTF-16 wide string and hash + XOR encrypt it at compile time
//! I think this *should* bake the ecrypted hash into the binary (rather than the raw string), but
//! I'm a fool so who really would know.

const K0: u64 = 0x9e37_79b9_7f4a_7c15;
const K1: u64 = 0xc2b2_ae3d_27d4_eb4f;
const K2: u64 = 0x1656_67b1_9e37_79f9;
const SEED: u64 = 0x5307_7d68_741d_7757;

#[inline]
const fn rotl(x: u64, r: u32) -> u64 {
    (x.rotate_left(r)) | (x >> (64 - r))
}

#[inline]
const fn mix(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(K1);
    h ^= h >> 29;
    h = h.wrapping_mul(K2);
    h ^= h >> 32;

    h
}

pub const fn hash_bytes(bytes: &[u8]) -> u64 {
    let mut h = SEED ^ (bytes.len() as u64).wrapping_mul(K0);
    let mut i = 0;

    while i + 8 <= bytes.len() {
        let block = u64::from_le_bytes([
            bytes[i],
            bytes[i + 1],
            bytes[i + 2],
            bytes[i + 3],
            bytes[i + 4],
            bytes[i + 5],
            bytes[i + 6],
            bytes[i + 7],
        ]);
        h ^= block.wrapping_mul(K1);
        h = rotl(h, 27).wrapping_mul(K0);
        i += 8;
    }

    let mut tail: u64 = 0;
    let mut shift = 0;
    while i < bytes.len() {
        tail |= (bytes[i] as u64) << shift;
        shift += 8;
        i += 1;
    }

    h ^= tail.wrapping_mul(K2);
    mix(h)
}

pub const fn next_rand(state: u64) -> (u64, u64) {
    let z0 = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = z0;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z = z ^ (z >> 31);

    (z0, z)
}

pub const fn xor_u16<const N: usize>(units: &[u16; N], seed: u64) -> [u16; N] {
    let mut out = [0u16; N];
    let mut state = seed;
    let mut i = 0;

    while i < N {
        let (s, r) = next_rand(state);
        state = s;
        out[i] = units[i] ^ (r as u16);
        i += 1;
    }

    out
}

pub const fn hash_str(s: &str) -> u64 {
    hash_bytes(s.as_bytes())
}

#[macro_export]
macro_rules! obfw {
    ($s:literal) => {{
        const N: usize = $crate::string::utf16_len($s);
        const SEED: u64 = $crate::hashing::hash_str($s);
        const PLAIN: [u16; N] = $crate::string::to_utf16::<N>($s);
        const CIPHER: [u16; N] = $crate::hashing::xor_u16(&PLAIN, SEED);

        // RT decrypt
        let mut buf = [0u16; N + 1];
        let key = $crate::hashing::xor_u16(&CIPHER, SEED);
        let mut i = 0;
        while i < N {
            buf[i] = key[i];
            i += 1;
        }

        buf[N] = 0;
        buf
    }};
}

/// This should fail at compile time if some required function is not consteval-able.
const _: () = {
    const N: usize = crate::string::utf16_len("HELLO53077d68741d7757");
    const PLAIN: [u16; N] = crate::string::to_utf16::<N>("HELLO53077d68741d7757");
    const CIPHER: [u16; N] = xor_u16(&PLAIN, hash_str("HELLO53077d68741d7757"));

    // cipher differs from plain at compile time
    let mut differ = false;
    let mut i = 0;
    while i < N {
        if CIPHER[i] != PLAIN[i] {
            differ = true;
        }
        i += 1;
    }
    assert!(differ);
};

#[cfg(test)]
mod test {
    extern crate alloc;

    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn obfw_roundtrips_to_expected() {
        let buf = obfw!("Aaa");
        let expected: Vec<u16> = "Aaa".encode_utf16().collect();

        assert_eq!(&buf[..buf.len() - 1], expected.as_slice());
    }

    #[test]
    fn obfw_null_terminated() {
        let buf = obfw!("hello");
        assert_eq!(*buf.last().unwrap(), 0);
    }

    #[test]
    fn obfw_handles_wide_chars() {
        let buf = obfw!("日本語 😀");
        let expected: Vec<u16> = "日本語 😀".encode_utf16().collect();
        assert_eq!(&buf[..buf.len() - 1], expected.as_slice());
    }

    #[test]
    fn obfw_empty_string() {
        let buf = obfw!("");
        assert_eq!(buf.len(), 1); // just the null
        assert_eq!(buf[0], 0);
    }

    #[test]
    fn cipher_differs_to_plain() {
        // catch broken keystream that leaves plaintext intact
        const S: &str = "hell o_日** 😀";
        const N: usize = crate::string::utf16_len(S);
        const PLAIN: [u16; N] = crate::string::to_utf16::<N>(S);

        let cipher = xor_u16(&PLAIN, hash_str(S));

        assert_ne!(&PLAIN[..], &cipher[..], "cipher must not equal plaintext");
    }

    #[test]
    fn xor_is_symmetric() {
        const S: &str = "hello_123 world 日本語 😀";
        const N: usize = crate::string::utf16_len(S);
        const PLAIN: [u16; N] = crate::string::to_utf16::<N>(S);

        let seed = hash_str(S);
        let cipher = xor_u16(&PLAIN, seed);
        let back = xor_u16(&cipher, seed);

        assert_eq!(PLAIN, back);
    }

    // sanity

    #[test]
    fn is_deterministic() {
        assert_eq!(hash_str(""), 0x0028a9c974caa37f);
        assert_eq!(hash_str("hello"), 0xbdcd8f6706e59971);
        assert_eq!(hash_str("0000*&Ah"), 0xdd5dbe33881194eb);
        assert_eq!(hash_str("café 日本語 😀"), 0x94927b0c484119f3);
    }

    #[test]
    fn hash_distinguishes_inputs() {
        assert_ne!(hash_str("a"), hash_str("A"));
        assert_ne!(hash_str("aaaa"), hash_str("Aaaa"));
        assert_ne!(hash_str("hello 123"), hash_str("hfllo 123"));
    }

    #[test]
    fn hash_avalanche_rough() {
        // a single-bit input change should flip a healthy number of output bits.
        let a = hash_str("test_string_a");
        let b = hash_str("test_string_b");
        let diff = (a ^ b).count_ones();
        assert!(diff >= 16, "weak avalanche: {diff} bits differ");
    }
}
