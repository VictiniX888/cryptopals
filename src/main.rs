#![allow(dead_code)]

use std::error::Error;

mod aes;
mod util;
mod xor;

fn main() -> Result<(), Box<dyn Error>> {
    let plaintexts: Vec<Vec<u8>> = include_str!("../assets/20.txt")
        .split_terminator('\n')
        .map(|str| util::base64_to_bytes(str))
        .collect();

    let nonce = 0u64.to_le_bytes();
    let ciphertexts = aes::ctr::fixed_nonce::encrypt_fixed_nonce_ctr(&plaintexts, &nonce);

    let decrypted = aes::ctr::fixed_nonce::decrypt_fixed_nonce_ctr_statistically(&ciphertexts);

    for bytes in decrypted {
        println!("{}", util::bytes_to_ascii(&bytes));
    }

    Ok(())
}
