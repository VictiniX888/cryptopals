use crate::{util, xor};
use openssl::{cipher::Cipher, cipher_ctx::CipherCtx};
use rand::{distributions::Uniform, thread_rng, Rng};

pub fn detect_aes_ecb_from_oracle(oracle: fn(&[u8]) -> Vec<u8>) -> bool {
    let bytes = [b'\0'; 16 * 3];
    let encrypted = oracle(&bytes);

    &encrypted[16..32] == &encrypted[32..48]
}

// Encrypts data under a random key, with either EBC or CBC mode (chosen randomly)
pub fn random_aes_mode_oracle(bytes: &[u8]) -> Vec<u8> {
    let mut rng = thread_rng();

    // Generate random 16-byte key
    let mut key = [0u8; 16];
    rng.fill(&mut key);

    // Generate random bytes to add to beginning and end of plaintext
    let add_len_range: Uniform<usize> = Uniform::new(5, 11);

    let prepend: Vec<u8> = (0..rng.sample(add_len_range)).map(|_| rng.gen()).collect();
    let mut append: Vec<u8> = (0..rng.sample(add_len_range)).map(|_| rng.gen()).collect();

    let mut bytes_modified = prepend;
    bytes_modified.extend_from_slice(bytes);
    bytes_modified.append(&mut append);

    let encrypted = if rng.gen() {
        // Use ECB half the time
        print!("ECB: ");
        encrypt_aes_ecb(&bytes_modified, &key)
    } else {
        // Use CBC half the time
        print!("CBC: ");
        let mut iv = [0u8; 16];
        rng.fill(&mut iv);
        encrypt_aes_cbc(&bytes_modified, &key, &iv)
    };

    encrypted
}

/* ========== CBC ========== */
pub fn decrypt_aes_cbc(bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    bytes
        .chunks(16)
        .map(|block| decrypt_aes_ecb(block, key))
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
        .collect()
}

pub fn encrypt_aes_cbc(bytes: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut encrypted: Vec<Vec<u8>> = pad_pkcs7(bytes, 16)
        .chunks(16)
        .map(|block| block.to_vec())
        .collect();
    let mut prev_ciphertext = iv.to_vec();
    for block in encrypted.iter_mut() {
        *block = xor::xor(&block, &prev_ciphertext);
        *block = encrypt_aes_ecb(&block, key);
        prev_ciphertext = block.clone();
    }

    encrypted.concat()
}

/* ========== ECB ========== */
pub fn detect_aes_ecb(messages: &Vec<Vec<u8>>) -> Vec<u8> {
    let mut messages_count: Vec<(&Vec<u8>, usize)> = messages
        .iter()
        .map(|msg| (msg, find_repeated_blocks(msg, 16)))
        .collect();
    messages_count.sort_by(|(_, c1), (_, c2)| c2.cmp(c1));

    for (message, count) in messages_count.iter() {
        println!("{}: {}", util::bytes_to_hex(message), count);
    }

    messages_count[0].0.to_vec()
}

pub fn encrypt_aes_ecb(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let mut ctx = CipherCtx::new().unwrap();
    ctx.encrypt_init(Some(cipher), Some(key), None).unwrap();
    ctx.set_padding(false);

    // Manually pad bytes only if not block size
    let bytes = if bytes.len() % 16 != 0 {
        pad_pkcs7(bytes, 16)
    } else {
        bytes.to_vec()
    };

    let mut encrypted = vec![];
    ctx.cipher_update_vec(&bytes, &mut encrypted).unwrap();
    ctx.cipher_final_vec(&mut encrypted).unwrap();

    encrypted
}

pub fn decrypt_aes_ecb(encrypted: &[u8], key: &[u8]) -> Vec<u8> {
    let cipher = Cipher::aes_128_ecb();
    let mut ctx = CipherCtx::new().unwrap();
    ctx.decrypt_init(Some(cipher), Some(key), None).unwrap();
    ctx.set_padding(false);

    let mut decrypted = vec![];
    ctx.cipher_update_vec(encrypted, &mut decrypted).unwrap();
    ctx.cipher_final_vec(&mut decrypted).unwrap();

    decrypted
}

/* ======== UTIL ======== */
pub fn pad_pkcs7(message: &[u8], block_size: usize) -> Vec<u8> {
    let mut pad_length = block_size - message.len() % block_size;
    if pad_length == 0 {
        pad_length = block_size;
    }

    assert!(pad_length < 256);

    let mut padded = Vec::from(message);
    padded.append(&mut vec![pad_length as u8; pad_length]);

    padded
}

fn find_repeated_blocks(message: &[u8], block_size: usize) -> usize {
    let mut count = 0;

    let blocks: Vec<&[u8]> = message.chunks_exact(block_size).collect();
    for (i, &b1) in blocks.iter().enumerate() {
        for &b2 in blocks.iter().skip(i + 1) {
            if b1 == b2 {
                count += 1;
            }
        }
    }

    count
}
