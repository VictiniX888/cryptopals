use rand::{thread_rng, Rng};

/* ======== PADDING ORACLE ATTACK ======== */
pub fn cbc_padding_oracle_attack(
    ciphertext: &[u8],
    iv: &[u8],
    oracle: impl Fn(&[u8]) -> bool,
) -> Vec<u8> {
    assert_eq!(ciphertext.len() % 16, 0);

    let mut plaintext: Vec<u8> = Vec::with_capacity(ciphertext.len());

    let mut prev_block = iv;
    for block in ciphertext.chunks_exact(16) {
        let mut xor_block = prev_block.to_vec();
        assert_eq!(xor_block.len(), 16);

        let mut inter_block: Vec<u8> = Vec::with_capacity(16);
        let mut plaintext_block: Vec<u8> = Vec::with_capacity(16);
        for i in (0..16).rev() {
            // Find byte which results in valid padding
            let mut b = u8::MIN;
            while b <= u8::MAX {
                xor_block[i] = b;
                let mut new_ciphertext = Vec::with_capacity(16 * 2);
                new_ciphertext.extend(&xor_block);
                new_ciphertext.extend_from_slice(block);
                let is_valid_padding = oracle(&new_ciphertext);

                if is_valid_padding {
                    if i == 0 {
                        break;
                    }
                    // Check if padding relies on prior bytes
                    // i.e. if this were the last byte, check if padding is only 0x01
                    new_ciphertext[i - 1] ^= 1;
                    let is_valid_padding = oracle(&new_ciphertext);
                    if is_valid_padding {
                        break;
                    }
                }

                b += 1;
            }

            // Find actual plaintext from that byte
            let inter_byte = b ^ (16 - i) as u8;
            inter_block.push(inter_byte);
            let plaintext_byte = inter_byte ^ prev_block[i];
            plaintext_block.push(plaintext_byte);

            for j in i..16 {
                xor_block[j] = inter_block[16 - j - 1] ^ (16 - i + 1) as u8;
            }
        }
        plaintext_block.reverse();
        plaintext.append(&mut plaintext_block);

        prev_block = block;
    }

    plaintext
}

// The oracle function returns true or false depending on whether the padding is valid
pub fn gen_aes_cbc_padding_oracle(
    plaintext: &[u8],
) -> (
    /* ciphertext */ Vec<u8>,
    /* iv */ Vec<u8>,
    /* oracle fn */ impl Fn(&[u8]) -> bool,
) {
    let mut rng = thread_rng();

    let key: [u8; 16] = rng.gen();
    let iv: [u8; 16] = rng.gen();

    let oracle = move |ciphertext: &[u8]| super::decrypt_aes_cbc(ciphertext, &key, &iv).is_ok();

    let ciphertext = super::encrypt_aes_cbc(plaintext, &key, &iv);

    (ciphertext, iv.to_vec(), oracle)
}
