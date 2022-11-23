pub mod cut_and_paste;

use crate::util;
use openssl::{cipher::Cipher, cipher_ctx::CipherCtx};
use rand::{thread_rng, Rng};

/* ========== ECB ========== */
pub fn decrypt_aes_ecb_with_oracle(oracle: impl Fn(&[u8]) -> Vec<u8>) -> Vec<u8> {
    let encrypted = oracle(&[]);

    // Find block offset
    let corrupted = oracle(&[0]);

    let offset = encrypted
        .iter()
        .zip(corrupted.iter())
        .enumerate()
        .find(|(_, (b1, b2))| b1 != b2)
        .unwrap()
        .0;

    // Find block size of cipher (should be 16)
    let mut block_size = 0;
    for i in 1..(encrypted.len() - offset) {
        if &oracle(&vec![0; i])[offset + i * 2..offset + i * 3]
            == &encrypted[offset + i..offset + i * 2]
        {
            block_size = i;
            break;
        }
    }
    assert_eq!(block_size, 16);

    assert_eq!(offset % block_size, 0);
    let offset_block = offset / block_size;

    // Find partial offset (block_size - extra prefix bytes in last prefix block)
    // This also checks if the function is using ECB
    let offset_partial = (1..=block_size).find(|i| {
        let encrypted = oracle(&vec![0; i + block_size * 2]);
        &encrypted[offset + block_size..offset + block_size * 2]
            == &encrypted[offset + block_size * 2..offset + block_size * 3]
    });

    assert_ne!(offset_partial, None);
    let offset_partial = offset_partial.unwrap();

    let mut unknown_string = Vec::with_capacity(encrypted.len());

    // Decrypt unknown string
    let aligned = oracle(&vec![0; offset_partial]);
    for block in offset_block + 1..aligned.len() / block_size {
        let mut input = vec![0; offset_partial + block_size];
        while input.len() > offset_partial {
            // Make input block that is 1 byte short
            input.pop();

            let encrypted = oracle(&input);

            // Match output
            for byte in u8::MIN..=u8::MAX {
                let mut input = input.clone();
                input.extend_from_slice(&unknown_string);
                input.push(byte);
                let matcher = oracle(&input);

                if &encrypted[block_size * block..block_size * (block + 1)]
                    == &matcher[block_size * block..block_size * (block + 1)]
                {
                    unknown_string.push(byte);
                    break;
                }
            }
        }
    }

    unknown_string
}

pub fn gen_aes_ecb_oracle_padded(unknown_string: &[u8]) -> impl Fn(&[u8]) -> Vec<u8> {
    let unknown_string = unknown_string.to_vec();

    let mut rng = thread_rng();

    let mut key = [0u8; 16];
    rng.fill(&mut key);

    let random_prefix: Vec<u8> = (0..rng.gen_range(0..=64)).map(|_| rng.gen()).collect();

    move |plaintext: &[u8]| {
        let mut input = random_prefix.clone();
        input.extend_from_slice(plaintext);
        aes_ecb_oracle(&input, &unknown_string, &key)
    }
}

pub fn gen_aes_ecb_oracle(unknown_string: &[u8]) -> impl Fn(&[u8]) -> Vec<u8> {
    let unknown_string = unknown_string.to_vec();
    let mut key = [0u8; 16];
    thread_rng().fill(&mut key);

    move |plaintext: &[u8]| aes_ecb_oracle(plaintext, &unknown_string, &key)
}

fn aes_ecb_oracle(plaintext: &[u8], unknown_string: &[u8], key: &[u8]) -> Vec<u8> {
    // Append unknown string to the input
    let mut bytes = plaintext.to_vec();
    bytes.extend_from_slice(unknown_string);

    encrypt_aes_ecb(&bytes, &key)
}

pub fn detect_aes_ecb(messages: &Vec<Vec<u8>>) -> Vec<u8> {
    let mut messages_count: Vec<(&Vec<u8>, usize)> = messages
        .iter()
        .map(|msg| (msg, super::find_repeated_blocks(msg, 16)))
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
        super::pad_pkcs7(bytes, 16)
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
