use std::{collections::VecDeque, iter::from_fn};

use super::ecb;
use crate::xor;

/* ======== CTR ======== */
pub fn decrypt_aes_ctr(ciphertext: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let keystream: Vec<u8> = ctr_keystream(key, nonce).take(ciphertext.len()).collect();

    xor::xor(ciphertext, &keystream)
}

pub fn encrypt_aes_ctr(plaintext: &[u8], key: &[u8], nonce: &[u8]) -> Vec<u8> {
    let keystream: Vec<u8> = ctr_keystream(key, nonce).take(plaintext.len()).collect();

    xor::xor(plaintext, &keystream)
}

fn ctr_keystream(key: &[u8], nonce: &[u8]) -> impl Iterator<Item = u8> {
    let key = key.to_vec();
    let nonce_len = nonce.len();

    let mut nonce_rev = nonce.to_vec();
    nonce_rev.reverse();

    let mut counter: u64 = 0;
    let mut keystream: VecDeque<u8> = VecDeque::with_capacity(16);

    from_fn(move || {
        if let Some(next) = keystream.pop_front() {
            Some(next)
        } else {
            nonce_rev.extend_from_slice(&counter.to_le_bytes());
            assert_eq!(nonce_rev.len(), 16);
            keystream.extend(ecb::encrypt_aes_ecb(&nonce_rev, &key));
            nonce_rev.truncate(nonce_len);
            counter += 1;

            keystream.pop_front()
        }
    })
}
