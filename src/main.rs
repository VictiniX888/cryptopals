#![allow(dead_code)]

mod aes;
mod util;
mod xor;

fn main() {
    let modified_profile = aes::ecb_cut_and_paste_admin_profile();
    println!("Plaintext: {}", util::bytes_to_ascii(&modified_profile));
}
