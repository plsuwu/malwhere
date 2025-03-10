use crate::crypt::aes::ks::{cbc_decrypt, cbc_encrypt, AesKey128};
use anyhow::anyhow;
use rand::{Fill, Rng};
use std::io::Read;
use std::ops::AddAssign;

/// ```ignore
/// VOID GenerateProtectedKey(
///     IN BYTE HintByte,
///     IN SIZE_T sKey,
///     OUT PBYTE *ppProtectedKey
/// ) {
///     // seed rand fn
///     srand(time(NULL));
///
///     BYTE    b               = (rand() % 0xFF) + 0x01;   // key of the key encr alg
///     PBYTE   pKey            = (PBYTE)malloc(sKey);      // stores original key
///     PBYTE   pProtectedKey   = (PBYTE)malloc(sKey);      // encrypted version of 'pKey' (via 'b')
///
///     if (!pKey || !pProtectedKey)
///         return;
///
///     // generate second seed
///     srand(time(NULL) * 2);
///
///     // key starts with hint byte
///     pKey[0] = HintByte;
///
///     // generate the rest of the key
///     for (int i = 1; i < sKey; i++) {
///         pKey[i] = (BYTE)srand() % 0xFF;
///     }
///
///     printf("[+] Generated key byte: 0x%0.2X \n\n", b);
///     printf("[+] Original key: ");
///     PrintHex(pKey, sKey);
///
///     // XOR key ('b') with the unencrypted key to get encrypted output
///     for (int i = 0; i < sKey; i++) {
///         pProtectedKey[i] = (BYTE)((pKey[i] + i) ^ b);
///     }
///
///     // save generated key
///     *ppProtectedKey = pProtectedKey;
///     free(pKey);
/// }
/// ```

pub trait ProtectedKey<const N: usize> {
    fn new() -> anyhow::Result<Self>
    where
        Self: Sized;

    fn key_from(hint: u8, key: Vec<u8>) -> anyhow::Result<Self>
    where
        Self: Sized;

    fn gen_pkey() -> anyhow::Result<[u8; N]> {
        let mut key = [0u8; N];
        rand::fill(&mut key[..]);

        Ok(key)
    }

    fn gen_subkey() -> u8 {
        rand::random::<u8>() + 0x01
    }

    fn xor_key(&mut self, rhs: u8);

    fn encrypt(&self, data: &[u8]) -> Vec<u8>;
    fn decrypt(&self, data: &[u8]) -> Vec<u8>;
}

#[derive(Debug, Clone)]
pub struct AesProtectedKey<const N: usize> {
    pub hint: u8,
    pub key: Vec<u8>,
}

impl<const N: usize> ProtectedKey<N> for AesProtectedKey<N> {
    fn new() -> anyhow::Result<Self> {
        let mut key = Self::gen_pkey()?;
        let hint = key[0];
        let subkey = Self::gen_subkey();

        let mut obj = Self {
            hint,
            key: key.to_vec(),
        };

        obj.xor_key(subkey);

        Ok(obj)
    }

    fn key_from(hint: u8, key: Vec<u8>) -> anyhow::Result<Self> {
        Ok(Self { hint, key })
    }

    fn xor_key(&mut self, rhs: u8) {
        self.key = self
            .key
            .iter()
            .enumerate()
            .map(|(i, byte)| (byte + i as u8) ^ rhs)
            .collect()
    }

    fn encrypt(&self, data: &[u8]) -> Vec<u8> {

        let mut real_key: [u8; 16] = [0; 16];
        real_key[..16].copy_from_slice(self.key.as_slice());

        let aes_key: AesKey128 = unsafe { std::mem::transmute(real_key) };

        cbc_encrypt(data, &aes_key)
    }

    fn decrypt(&self, data: &[u8]) -> Vec<u8> {
        let mut real_key: [u8; 16] = [0; 16];
        real_key[..16].copy_from_slice(self.key.as_slice());

        let aes_key: AesKey128 = unsafe { std::mem::transmute(real_key) };

        let res = cbc_decrypt(data, aes_key);
        if let Some(r) = res {
            return r
        } else {
            panic!("decrypt failed");
        }

    }
}

impl<const N: usize> AesProtectedKey<N> {
    pub fn brute(&mut self) -> Vec<u8> {
        let mut rhs = 0u8;
        while self.reverse_xor(rhs)[0] != self.hint &&
            rhs <= 0xff
        {
            rhs.add_assign(1);
        }

        self.reverse_xor(rhs)
    }

    fn reverse_xor(&mut self, rhs: u8) -> Vec<u8> {
        self.key
            .iter()
            .enumerate()
            .map(|(i, byte)| (byte ^ rhs) - i as u8)
            .collect()
    }
}
