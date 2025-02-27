//! LoseLose hash function implementation

use super::traits::HashFunction;

pub struct LoseLose;

impl HashFunction for LoseLose { 
    type Output = u32;

    fn hash_str(&self, s: &str) -> Self::Output {
        let mut hash: u32 = 0;

        for b in s.bytes() {
            hash += b as u32;
        }

        hash
    }

    fn hash_vec(&self, v: Vec<&str>) -> Vec<Self::Output> {
        let res = v.iter().map(|s| self.hash_str(*s)).collect::<Vec<_>>();
        res
    }
}
