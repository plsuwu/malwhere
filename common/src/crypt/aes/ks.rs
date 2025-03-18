use alloc::borrow::ToOwned;
use alloc::vec::Vec;
use rand::{Rng, SeedableRng};
use rand::rngs::SmallRng;
use super::table::*;
use core::mem::transmute;
use libc_print::{libc_print, libc_println};

pub type AesColumn = [u8; 4];
pub type AesBlock = [AesColumn; 4];
pub type AesKey128 = [u8; 16];

pub fn gf_mult(a: u8, b: u8) -> u8 {
    let mut result: u16 = 0;
    let mut a: u16 = a as u16;
    let mut b: u8 = b;

    // loop through each bit in `b`
    for _ in 0..8 {
        // if b's LSB is set (i.e, we are not multiplying out by 0 for this term)
        // xor the result with `a` (equiv. to adding polynomial terms of a)
        if b & 1 == 1 {
            result ^= a;
        }

        // track a's MSB to determine whether `a` is still within
        // the bounds of the field
        let msb = a & 0x80;
        a <<= 1; // double a

        // next bit in `b` represents multiplying a's terms by the next power
        // of 2 (equiv. to shifting `a` left) - need to modulo with irreducible
        // polynomial term if `a` left the field
        if msb != 0 {
            a ^= 0x11b;
        }

        // shift `b` right to operate on the next bit (worth twice as much
        // in the multiplication)
        b >>= 1;
    }

    return result as u8;
}

pub fn gf_word_add(a: AesColumn, b: AesColumn, dest: &mut AesColumn) {
    dest[0] = a[0] ^ b[0];
    dest[1] = a[1] ^ b[1];
    dest[2] = a[2] ^ b[2];
    dest[3] = a[3] ^ b[3];
}

pub fn key_schedule_128(key: &AesKey128, keys_out: &mut [AesBlock; NUM_ROUND_KEYS_128]) {
    // `AesBlock` and `AesKey128` are both 16-byte structures
    // [[u8; 4]; 4] -> [u8; 16]
    let key_block: &AesBlock = unsafe { transmute(key) };
    keys_out[0] = *key_block;

    let mut col_c = keys_out[0][3];
    for i in 0..NUM_ROUND_KEYS_128 - 1 {
        rot_word(&mut col_c);
        sub_word(&mut col_c, &SBOX_ENCRYPT);
        gf_word_add(col_c, RCON[i], &mut col_c);

        // compute the next key round
        gf_word_add(col_c, keys_out[i][0], &mut keys_out[i + 1][0]);
        gf_word_add(keys_out[i + 1][0], keys_out[i][1], &mut keys_out[i + 1][1]);
        gf_word_add(keys_out[i + 1][1], keys_out[i][2], &mut keys_out[i + 1][2]);
        gf_word_add(keys_out[i + 1][2], keys_out[i][3], &mut keys_out[i + 1][3]);

        // update last col for next round
        col_c = keys_out[i + 1][3];
    }
}

pub fn mix_columns(state: &mut AesBlock) {
    let mut tmp: AesColumn = [0, 0, 0, 0];

    for i in 0..4 {
        tmp[0] =
            gf_mult(0x02, state[i][0]) ^ gf_mult(0x03, state[i][1]) ^ state[i][2] ^ state[i][3];
        tmp[1] =
            state[i][0] ^ gf_mult(0x02, state[i][1]) ^ gf_mult(0x03, state[i][2]) ^ state[i][3];
        tmp[2] =
            state[i][0] ^ state[i][1] ^ gf_mult(0x02, state[i][2]) ^ gf_mult(0x03, state[i][3]);
        tmp[3] =
            gf_mult(0x03, state[i][0]) ^ state[i][1] ^ state[i][2] ^ gf_mult(0x02, state[i][3]);

        state[i][0] = tmp[0];
        state[i][1] = tmp[1];
        state[i][2] = tmp[2];
        state[i][3] = tmp[3];
    }
}

pub fn inv_mix_columns(state: &mut AesBlock) {
    let mut tmp: AesColumn = [0, 0, 0, 0];

    for i in 0..4 {
        tmp[0] = gf_mult(0x0e, state[i][0])
            ^ gf_mult(0x0b, state[i][1])
            ^ gf_mult(0x0d, state[i][2])
            ^ gf_mult(0x09, state[i][3]);

        tmp[1] = gf_mult(0x09, state[i][0])
            ^ gf_mult(0x0e, state[i][1])
            ^ gf_mult(0x0b, state[i][2])
            ^ gf_mult(0x0d, state[i][3]);

        tmp[2] = gf_mult(0x0d, state[i][0])
            ^ gf_mult(0x09, state[i][1])
            ^ gf_mult(0x0e, state[i][2])
            ^ gf_mult(0x0b, state[i][3]);

        tmp[3] = gf_mult(0x0b, state[i][0])
            ^ gf_mult(0x0d, state[i][1])
            ^ gf_mult(0x09, state[i][2])
            ^ gf_mult(0x0e, state[i][3]);

        state[i][0] = tmp[0];
        state[i][1] = tmp[1];
        state[i][2] = tmp[2];
        state[i][3] = tmp[3];
    }
}

pub fn rot_word(word: &mut AesColumn) {
    let tmp = word[0];
    word[0] = word[1];
    word[1] = word[2];
    word[2] = word[3];
    word[3] = tmp;
}

pub fn sub_bytes(state: &mut AesBlock, table: &[u8]) {
    let mut index: usize;

    for col in 0..4 {
        for row in 0..4 {
            index = state[col][row] as usize;
            state[col][row] = table[index];
        }
    }
}

pub fn sub_word(word: &mut AesColumn, table: &[u8]) {
    let mut index: usize;

    for i in 0..4 {
        index = word[i] as usize;
        word[i] = table[index];
    }
}

pub fn shift_rows(state: &mut [[u8; 4]; 4]) {
    let mut tmp_a: u8;
    let tmp_b: u8;

    // shift row 1
    // [0] [1] [2] [3] --> [1] [2] [3] [0]
    tmp_a = state[0][1];
    state[0][1] = state[1][1];
    state[1][1] = state[2][1];
    state[2][1] = state[3][1];
    state[3][1] = tmp_a;

    // shift row 2
    // [0] [1] [2] [3] --> [2] [3] [0] [1]
    tmp_a = state[0][2];
    tmp_b = state[1][2];
    state[0][2] = state[2][2];
    state[1][2] = state[3][2];
    state[2][2] = tmp_a;
    state[3][2] = tmp_b;

    //shift row 3
    //[0] [1] [2] [3] --> [3] [0] [1] [2]
    tmp_a = state[3][3];
    state[3][3] = state[2][3];
    state[2][3] = state[1][3];
    state[1][3] = state[0][3];
    state[0][3] = tmp_a;
}

pub fn inv_shift_rows(state: &mut [[u8; 4]; 4]) {
    let mut tmp_a: u8;
    let tmp_b: u8;

    // shift row 1
    // [0] [1] [2] [3] --> [3] [0] [1] [2]
    tmp_a = state[3][1];
    state[3][1] = state[2][1];
    state[2][1] = state[1][1];
    state[1][1] = state[0][1];
    state[0][1] = tmp_a;

    // shift row 2
    // [0] [1] [2] [3] --> [2] [3] [0] [1]
    tmp_a = state[0][2];
    tmp_b = state[1][2];
    state[0][2] = state[2][2];
    state[1][2] = state[3][2];
    state[2][2] = tmp_a;
    state[3][2] = tmp_b;

    // shift row 3
    // [0] [1] [2] [3] --> [1] [2] [3] [0]
    tmp_a = state[0][3];
    state[0][3] = state[1][3];
    state[1][3] = state[2][3];
    state[2][3] = state[3][3];
    state[3][3] = tmp_a;
}

pub fn add_round_key(state: &mut AesBlock, round_key: &AesBlock) {
    for col in 0..4 {
        for row in 0..4 {
            state[col][row] ^= round_key[col][row];
        }
    }
}

pub fn encrypt_block(state: &mut AesBlock, key_schedule: &[AesBlock]) {

    add_round_key(state, &key_schedule[0]);
    for i in 1..NUM_ROUND_KEYS_128 {
        sub_bytes(state, &SBOX_ENCRYPT);
        shift_rows(state);

        // opting out of a column mix on the last round like this
        // constitutes a timing-based side-channel risk
        if i < NUM_ROUND_KEYS_128 - 1 {
            mix_columns(state);
        }

        add_round_key(state, &key_schedule[i]);
    }
}

pub fn decrypt_block(state: &mut AesBlock, key_schedule: &[AesBlock]) {

    let mut rnd = NUM_ROUND_KEYS_128 - 1;
    for i in 1..NUM_ROUND_KEYS_128 {
        add_round_key(state, &key_schedule[rnd]);
        rnd = rnd.wrapping_sub(1);

        if i != 1 {
            inv_mix_columns(state);
        }

        inv_shift_rows(state);
        sub_bytes(state, &SBOX_DECRYPT);
    }

    add_round_key(state, &key_schedule[0])
}

fn transmute_and_encrypt(
    state: &[u8; 16],
    output: &mut Vec<u8>,
    key_schedule: &[AesBlock; NUM_ROUND_KEYS_128],
) -> [u8; 16] {
    unsafe {
        let mut block: AesBlock = transmute(state.to_owned());
        encrypt_block(&mut block, key_schedule);
        let encrypted: [u8; 16] = transmute(block);
        output.extend_from_slice(&encrypted);

        //prev_state = encrypted;
        return encrypted;
    }
}

pub fn cbc_encrypt(input: &[u8], key: &AesKey128) -> Vec<u8> {

    // not a cryptographically secure IV generation implementation
    let mut iv = [0u8; 16];
    let mut rng = SmallRng::from_os_rng();
    rng.fill(&mut iv[..]);

    libc_println!("\niv:");
    for byte in iv {
        libc_print!("{:02x?}", byte);
    }
    libc_println!();

    let mut prev_state = iv;

    let padding = 16 - (input.len() % 16);
    let padding = if padding == 0 { 16 } else { padding };

    let output_size = input.len() + padding + 16;
    let mut output = Vec::with_capacity(output_size);
    output.extend_from_slice(&iv);

    let mut key_schedule: [AesBlock; NUM_ROUND_KEYS_128] = Default::default();
    key_schedule_128(key, &mut key_schedule);

    let mut input_offset = 0;

    while input_offset < input.len() {
        let mut state = [0u8; 16];
        let bytes_remaining = input.len() - input_offset;
        let block_size = bytes_remaining.min(16);

        // fill block from input with indexation from the current block up to a maximum block size
        // of 16 bytes
        state[..block_size].copy_from_slice(&input[input_offset..input_offset + block_size]);

        // if we are on the final block and there was not enough remaining input data, pad out the
        // remaining bytes to reach the expected block size
        if block_size < 16 {
            for i in block_size..16 {
                state[i] = padding as u8;
            }
        }

        for (curr, prev) in state.iter_mut().zip(prev_state.iter()) {
            *curr ^= prev;
        }
        //for i in 0..16 {
        //    state[i] ^= prev_state[i];
        //}

        prev_state = transmute_and_encrypt(&state, &mut output, &key_schedule);
        input_offset += 16;
    }

    if padding == 16 && input.len() % 16 == 0 {
        let mut state = [padding as u8; 16];
        for (curr, prev) in state.iter_mut().zip(prev_state.iter()) {
            *curr ^= prev;
        }

        let _prev_state = transmute_and_encrypt(&state, &mut output, &key_schedule);
    }

    return output;
}

pub fn cbc_decrypt(input: &[u8], key: AesKey128) -> Option<Vec<u8>> {
    // retrieve iv
    let mut prev_state = &input[..16];
    let mut key_schedule: [AesBlock; NUM_ROUND_KEYS_128] = Default::default();
    key_schedule_128(&key, &mut key_schedule);

    let mut output = Vec::with_capacity(input.len() - 16);
    let mut last_byte = 0u8;
    let mut input_offset = 16;

    while input_offset < input.len() {
        let curr_block = &input[input_offset..input_offset + 16];

        unsafe {
            let mut state: AesBlock =
                transmute(*<&[u8; 16]>::try_from(curr_block).unwrap());
            decrypt_block(&mut state, &key_schedule);

            let mut decrypted: [u8; 16] = transmute(state);
            for (curr, prev) in decrypted.iter_mut().zip(prev_state.iter()) {
                *curr ^= prev;
            }

            // verify padding if curr_block is the last block
            if input_offset + 16 == input.len() {
                last_byte = decrypted[15];
                if last_byte == 0 || last_byte > 16 {
                    return None;
                }

                for i in 16 - last_byte..15 {
                    if decrypted[i as usize] != last_byte {
                        return None;
                    }
                }
            }

            output.extend_from_slice(&decrypted);
        }

        input_offset += 16;
        prev_state = curr_block;
    }

    output.truncate(output.len() - last_byte as usize);
    return Some(output);
}