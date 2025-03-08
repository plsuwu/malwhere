use crate::hashing::traits::HashFunction;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Crc32b;

const SEED: u32 = 0xedb88320;

const fn g() -> [u32; 8] {
    let mut buff = [
        SEED,
        SEED.wrapping_shr(1),
        SEED.wrapping_shl(2),
        SEED.wrapping_shr(3),
        SEED.wrapping_shl(4),
        SEED.wrapping_shr(5),
        0,
        0
    ];

    buff[6] = SEED.wrapping_shr(6) ^ SEED;
    buff[7] = (SEED.wrapping_shr(6) ^ SEED).wrapping_shr(1);

    buff
}

impl HashFunction for Crc32b {
    type Output = u32;

    fn hash_str(&self, s: &str) -> Self::Output {
        #[allow(unused_assignments)]
        let mut mask: u32 = 0xffffffff;

        let mut crc: u32 = 0xffffffff;
        for b in s.bytes() {
            crc ^= b as u32;
            for _ in (0..8).rev() {
                mask = ((-1i32) as u32).wrapping_mul(crc & 1);
                crc = (crc.wrapping_shr(1)) ^ (SEED & mask);
            }
        }

        !crc
    }
}

/// Broken implementation
#[derive(Debug, Copy, Clone, PartialEq)]
struct Crc32h;

impl HashFunction for Crc32h {
    type Output = u32;
    fn hash_str(&self, s: &str) -> Self::Output {
        let mut crc: u32 = 0xffffffff;
        const G: [u32;8] = g();

        for b in s.bytes() {
            crc ^= b as u32;
            let c =
                ((crc.wrapping_shl(31).wrapping_shr(31)) & G[7])
                ^ (crc.wrapping_shl(30).wrapping_shr(31) & G[6])
                ^ (crc.wrapping_shl(29).wrapping_shr(31) & G[5])
                ^ (crc.wrapping_shl(28).wrapping_shr(31) & G[4])
                ^ (crc.wrapping_shl(27).wrapping_shr(31) & G[3])
                ^ (crc.wrapping_shl(26).wrapping_shr(31) & G[2])
                ^ (crc.wrapping_shl(25).wrapping_shr(31) & G[1])
                ^ (crc.wrapping_shl(24).wrapping_shr(31) & G[0]);
            crc = crc.wrapping_shr(8) ^ c;
        }

        !crc
    }
}

