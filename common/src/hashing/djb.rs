//! Djb hash function implementation

use std::ops::AddAssign;
use super::traits::HashFunction;

#[derive(Debug, Copy, Clone, PartialEq)]
pub struct Djb;

impl HashFunction for Djb {
    type Output = u32;

    fn hash_str(&self, s: &str) -> Self::Output {
        let mut hash: u32 = 5387;
        for b in s.bytes() {
            hash = (hash << 5).wrapping_add(hash).wrapping_add(b as _);
        }

        hash
    }
}

#[cfg(test)]
mod tests {
    use super::super::traits::StringHasher;
    use super::*;

    #[test]
    fn test_str() {
        let plain = "test_string 00";
        // let expects = 0xa6345cf39b03dac1;

        let djb = StringHasher::new(Djb);
        let output = djb.hash(plain);

        assert_eq!(expects, output);
    }
}

