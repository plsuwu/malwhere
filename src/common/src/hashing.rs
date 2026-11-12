//! A vague implementation using parts from like three or four different hashing algorithms.

pub const HASH_SEED: u64 = 0x5307_7d68_741d_7757;
pub const XOR_SEED: u64 = 0x406f_334c_566a_7625;
const K0: u64 = 0x9e37_79b9_7f4a_7c15;
const P2: u64 = 0xc2b2_ae3d_27d4_eb4f;
const P3: u64 = 0x1656_67b1_9e37_79f9;
const MM1: u64 = 0x3c79_ac49_2ba7_b653;
const MM2: u64 = 0x1c69_b3f7_4ac4_ae35;

/// PRNG from [`Splitmix64`].
///
/// Returns `(next_state, output)` tuple.
///
/// [`Splitmix64`]: https://rosettacode.org/wiki/Pseudo-random_numbers/Splitmix64
pub const fn next_rand(state: u64) -> (u64, u64) {
    let z0 = state.wrapping_add(K0);
    let mut z = z0;

    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z = z ^ (z >> 31);
    (z0, z)
}

#[inline]
const fn fold_mul(a: u64, b: u64) -> u64 {
    let p = (a as u128).wrapping_mul(b as u128);
    (p as u64) ^ ((p >> 64) as u64)
}

#[inline]
const fn xxh_avalanche(mut h: u64) -> u64 {
    h ^= h >> 33;
    h = h.wrapping_mul(P2);
    h ^= h >> 29;
    h = h.wrapping_mul(P3);
    h ^= h >> 32;
    h
}

#[inline]
const fn moremur(mut x: u64) -> u64 {
    x ^= x >> 27;
    x = x.wrapping_mul(MM1);
    x ^= x >> 33;
    x = x.wrapping_mul(MM2);
    x ^= x >> 27;
    x
}

/// Round multipliers and seed for the key schedule
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key {
    m: [u64; 4],
    seed: u64,
}

/// Loop over Splitmix64 outputs until we find a usable multiplier
const fn pick_multiplier(mut state: u64) -> (u64, u64) {
    loop {
        let (s, r) = next_rand(state);
        state = s;
        let m = r | 1;
        let pc = m.count_ones();

        if pc >= 28 && pc <= 36 {
            return (state, m);
        }
    }
}

pub const fn derive_key(seed: u64) -> Key {
    let mut m = [0u64; 4];
    let mut state = seed;

    let mut i = 0;
    while i < 4 {
        let (s, v) = pick_multiplier(state);

        state = s;
        m[i] = v;
        i += 1;
    }

    Key { m, seed }
}

pub const DEFAULT_KEY: Key = derive_key(HASH_SEED);

/// Pack four `u16`s into a single `u64` (little-endian)
#[inline]
const fn lane4(d: &[u16], i: usize) -> u64 {
    (d[i] as u64)
        | ((d[i + 1] as u64) << 16)
        | ((d[i + 2] as u64) << 32)
        | ((d[i + 3] as u64) << 48)
}

#[inline]
const fn round(acc: u64, lane: u64, k: &Key, r: u32) -> u64 {
    let x = acc.wrapping_add(lane.wrapping_mul(k.m[0]));
    x.rotate_left(r).wrapping_mul(k.m[1])
}

pub const fn hash_u16_keyed(data: &[u16], k: &Key) -> u64 {
    let len = data.len();
    let len_bytes = (len as u64).wrapping_mul(2);

    let mut acc_a = k.seed ^ len_bytes.wrapping_mul(K0) ^ k.m[2];
    let mut acc_b = k.seed.rotate_left(32) ^ len_bytes ^ k.m[3];

    let mut w = k.seed;
    let mut i = 0;
    while i + 8 <= len {
        w = w.wrapping_add(K0);
        acc_a = round(acc_a, lane4(data, i) ^ w, k, 31);
        w = w.wrapping_add(K0);
        acc_b = round(acc_b, lane4(data, i + 4) ^ w, k, 29);
        i += 8;
    }

    let mut h = fold_mul(acc_a ^ k.m[2], acc_b ^ k.m[3]) ^ acc_a ^ acc_b.rotate_left(17);

    while i + 4 <= len {
        w = w.wrapping_add(K0);
        h ^= round(0, lane4(data, i) ^ w, k, 31);
        h = h.rotate_left(27).wrapping_mul(k.m[1]).wrapping_add(k.m[3]);
        i += 4;
    }

    if i < len {
        let mut tail: u64 = 0;
        let mut shift = 0;
        while i < len {
            tail |= (data[i] as u64) << shift;
            shift += 16;
            i += 1;
        }

        w = w.wrapping_add(K0);
        h ^= fold_mul(tail ^ k.m[0], w ^ k.m[2]);
        h = h.rotate_left(23).wrapping_mul(k.m[1]);
    }

    moremur(xxh_avalanche(h ^ len_bytes))
}

pub const fn hash_u16_seeded(data: &[u16], seed: u64) -> u64 {
    if seed == HASH_SEED {
        hash_u16_keyed(data, &DEFAULT_KEY)
    } else {
        // rebuilds key using `seed` on every call that doesn't pass `HASH_SEED`
        hash_u16_keyed(data, &derive_key(seed))
    }
}

pub const fn hash_u16(data: &[u16]) -> u64 {
    hash_u16_keyed(data, &DEFAULT_KEY)
}

pub const fn xor_hash(input: u64) -> u64 {
    let (_, r) = next_rand(input ^ XOR_SEED);
    xxh_avalanche(r ^ XOR_SEED)
}

/// Macro to perform hashing on `&str` literals at compile time
///
/// # Usage
///
/// Pass a `const`-scoped `&str` along with a reference to a `Key`; `common::hashing::DEFAULT_KEY` is a
/// pre-computed "default", or one can be constructed via `common::hashing::derive_key` (which takes
/// a `seed` value as its parameter):
///
/// ```
/// // using the default key
/// assert_eq!(
///     widehash!("hello 123", &DEFAULT_KEY),
///     0x39C9_13CE_D12F_7411
/// );
///
/// // using a custom derived key
/// assert_eq!(
///     widehash!("hello 123", &derive_key(XOR_SEED)),
///     0x39C9_13CE_D12F_7411
/// );
/// ```
#[macro_export]
macro_rules! widehash {
    ($s:expr, $k:expr) => {{
        const LEN: usize = $crate::winstring::str_utf16_len($s);
        const HASH: u64 =
            $crate::hashing::hash_u16_keyed(&$crate::winstring::str_to_utf16::<LEN>($s), $k);

        $crate::hashing::xor_hash(HASH)
    }};
}

#[cfg(test)]
mod test {
    extern crate std;

    use std::collections::HashSet;

    use super::*;

    #[test]
    fn key_multipliers_match() {
        for seed in [0u64, 1, HASH_SEED, u64::MAX] {
            let k = derive_key(seed);
            for m in k.m {
                assert_eq!(m & 1, 1);
                assert!((28..=36).contains(&m.count_ones()));
            }
        }

        std::println!("DEFAULT_KEY multipliers: {:#018x?}", DEFAULT_KEY.m);
    }

    #[test]
    fn regressions_from_original() {
        assert_ne!(hash_u16(&[0x0041; 8]), hash_u16(&[0x0141; 8]));
        assert_ne!(hash_u16(&[0x0041]), hash_u16(&[0x0141]));
        assert_ne!(hash_u16(&[0x0100, 0x0000]), hash_u16(&[0x0000, 0x0001]));

        let a = xor_hash(0);
        assert_ne!(a ^ xor_hash(1), 1);
    }

    #[test]
    fn length_and_zero_inputs() {
        let mut seen = HashSet::new();
        for n in 0..200 {
            assert!(
                seen.insert(hash_u16(&std::vec![0u16; n])),
                "zero-run collision: @{n}"
            );
        }
    }

    #[test]
    fn position_affects_output() {
        // same overall block content but right-shifted 4 indices
        let x = [1u16, 2, 3, 4, 5, 6, 7, 8];
        let y = [5u16, 6, 7, 8, 1, 2, 3, 4];
        assert_ne!(hash_u16(&x), hash_u16(&y));

        // same bit in lane_a and lane_b
        let mut z1 = [0u16; 16];
        let mut z2 = [0u16; 16];
        z1[0] = 1;
        z2[8] = 1;
        assert_ne!(hash_u16(&z1), hash_u16(&z2));
    }

    #[test]
    fn seed_does_full_change() {
        let d = [1u16, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
        assert_ne!(hash_u16_seeded(&d, 1), hash_u16_seeded(&d, 2));
        assert_eq!(hash_u16_seeded(&d, HASH_SEED), hash_u16(&d));
    }

    #[test]
    fn widehash_macro_with_default_key() {
        const TEST_STR: &str = "hello 123";
        const HASHED: u64 = crate::widehash!(TEST_STR, &DEFAULT_KEY);

        assert_eq!(HASHED, 0x39C9_13CE_D12F_7411);
    }

    #[test]
    fn widehash_macro_with_seeded_key() {
        const TEST_STR: &str = "hello 123";
        const HASHED: u64 = crate::widehash!(TEST_STR, &derive_key(XOR_SEED));

        assert_eq!(HASHED, 0xE7CA_E18D_8CE2_EFC1);
    }
}
