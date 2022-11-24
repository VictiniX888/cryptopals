#![allow(dead_code)]

use std::error::Error;

mod aes;
mod util;
mod xor;

fn main() -> Result<(), Box<dyn Error>> {
    let plaintext = aes::cbc::bitflipping::cbc_bitflipping_attack_admin();
    println!("Modified plaintext: {}", util::bytes_to_ascii(&plaintext));

    Ok(())
}
