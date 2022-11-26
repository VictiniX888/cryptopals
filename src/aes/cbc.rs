pub mod bitflipping;
pub mod padding_oracle;

use super::ecb;
use crate::xor;

/* ========== CBC ========== */
pub fn decrypt_aes_cbc(bytes: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>, String> {
    let padded: Vec<u8> = bytes
        .chunks(16)
        .map(|block| ecb::decrypt_aes_ecb(block, key))
        .enumerate()
        .flat_map(|(i, block)| {
            xor::xor(
                &block,
                if i == 0 {
                    iv
                } else {
                    &bytes[(i - 1) * 16..i * 16]
                },
            )
        })
        .collect();

    Ok(super::strip_pkcs7(&padded)?)
}

pub fn encrypt_aes_cbc(bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut encrypted: Vec<Vec<u8>> = super::pad_pkcs7(bytes, 16)
        .chunks(16)
        .map(|block| block.to_vec())
        .collect();
    let mut prev_ciphertext = iv.to_vec();
    for block in encrypted.iter_mut() {
        *block = xor::xor(&block, &prev_ciphertext);
        *block = ecb::encrypt_aes_ecb(&block, key);
        prev_ciphertext = block.clone();
    }

    encrypted.concat()
}
