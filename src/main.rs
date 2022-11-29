#![allow(dead_code)]

use std::error::Error;

mod aes;
mod mt19937;
mod util;
mod xor;

fn main() -> Result<(), Box<dyn Error>> {
    let mut rng = mt19937::MT19937::new(5489);
    println!("{}", rng.nth(9999).unwrap());

    Ok(())
}
