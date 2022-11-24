#![allow(dead_code)]

use std::error::Error;

mod aes;
mod util;
mod xor;

fn main() -> Result<(), Box<dyn Error>> {
    let padded = util::ascii_to_bytes("ICE ICE BABY\x01\x02\x03\x04");

    let stripped = aes::strip_pkcs7(&padded)?;

    println!("{}", util::bytes_to_ascii(&stripped));

    Ok(())
}
