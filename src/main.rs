#![allow(dead_code)]

use std::error::Error;

mod aes;
mod util;
mod xor;

fn main() -> Result<(), Box<dyn Error>> {
    aes::ctr::fixed_nonce::decrypt_fixed_nonce_ctr_substitution();

    Ok(())
}
