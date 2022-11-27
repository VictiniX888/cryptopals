#![allow(dead_code)]

use std::error::Error;

mod aes;
mod util;
mod xor;

fn main() -> Result<(), Box<dyn Error>> {
    let ciphertext = util::base64_to_bytes(
        "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==",
    );
    let key = b"YELLOW SUBMARINE";
    let nonce = 0u64.to_le_bytes();
    assert!(nonce.len() == 8);

    let plaintext = aes::ctr::decrypt_aes_ctr(&ciphertext, key, &nonce);
    println!("{}", util::bytes_to_ascii(&plaintext));

    Ok(())
}
