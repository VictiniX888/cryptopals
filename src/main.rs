#![allow(dead_code)]

mod aes;
mod util;
mod xor;

fn main() {
    for _ in 0..1000 {
        let is_ecb = aes::detect_aes_ecb_from_oracle(aes::random_aes_mode_oracle);
        println!("{}", if is_ecb { "ECB" } else { "CBC" });
    }
}
