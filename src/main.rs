#![allow(dead_code)]

mod aes;
mod util;
mod xor;

fn main() {
    let unknown_string = util::base64_to_bytes(
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
                aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
                dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
                YnkK",
    );

    let oracle = aes::ecb::gen_aes_ecb_oracle_padded(&unknown_string);

    let decrypted = aes::ecb::decrypt_aes_ecb_with_oracle(oracle);

    println!("{}", util::bytes_to_ascii(&decrypted));
}
