//! Fowler-Noll-Vo hash function implementation

use core::ops::BitXor;
use super::traits::HashFunction;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Fnv;

impl HashFunction for Fnv {
    type Output = u32;

    fn hash_str(&self, s: &str) -> Self::Output {
        let mut hash: u64 = 0xcbf29ce484222325;

        for b in s.bytes() {
            hash = hash.bitxor(b as u64);
            hash = hash.wrapping_mul(0x100000001b3);
        }

        hash as u32
    }
}