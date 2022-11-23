use crate::{util, xor};
use openssl::{cipher::Cipher, cipher_ctx::CipherCtx};
use rand::{distributions::Uniform, thread_rng, Rng};

/* ======== ECB CUT-AND-PASTE ATTACK ======== */
pub fn ecb_cut_and_paste_admin_profile() -> Vec<u8> {
    // Generate "valid" profiles
    // This gives us "email=foooo@bar. | com&uid=10&role= | user"
    // (| marks each block and is visual only)
    let base = profile_for("foooo@bar.com");
    println!("Encoded: {}", base);

    // This gives us "email=aaaaaaaaaa | admin\v\v\v\v\v\v\v\v\v\v\v | &uid=10&role=use | r"
    // \v is ASCII 11, we use it as padding
    let admin = profile_for(
        &("aaaaaaaaaaadmin".to_string()
            + &[11u8; 11]
                .iter()
                .map(|&byte| byte as char)
                .collect::<String>()),
    );
    println!("Admin string: {}", admin);

    let (encrypt, decrypt) = gen_aes_ecb_encrypt_decrypt_oracles();

    // Generate "valid" ciphertexts from valid profiles
    let ciphertext_base = encrypt(&util::ascii_to_bytes(&base));
    println!("Base ciphertext: {}", util::bytes_to_hex(&ciphertext_base));

    let ciphertext_admin = encrypt(&util::ascii_to_bytes(&admin));
    println!(
        "Admin ciphertext: {}",
        util::bytes_to_hex(&ciphertext_admin)
    );

    // Cut and paste the ciphertexts to form admin profile
    let mut ciphertext_combined = Vec::from(&ciphertext_base[..32]);
    ciphertext_combined.extend_from_slice(&ciphertext_admin[16..32]);
    println!(
        "Combined ciphertext: {}",
        util::bytes_to_hex(&ciphertext_combined)
    );

    let plaintext = decrypt(&ciphertext_combined);

    plaintext
}

pub fn gen_aes_ecb_encrypt_decrypt_oracles(
) -> (impl Fn(&[u8]) -> Vec<u8>, impl Fn(&[u8]) -> Vec<u8>) {
    let mut key = [0u8; 16];
    thread_rng().fill(&mut key);

    (
        move |plaintext: &[u8]| encrypt_aes_ecb(plaintext, &key),
        move |ciphertext: &[u8]| decrypt_aes_ecb(ciphertext, &key),
    )
}

pub fn profile_for(email: &str) -> String {
    let profile = [
        ("email".to_string(), email.to_string()),
        ("uid".to_string(), 10u8.to_string()),
        ("role".to_string(), "user".to_string()),
    ];

    encode_to_query_string(&profile)
}

/* ======== BOTH ======== */
pub fn detect_aes_ecb_from_oracle(oracle: impl Fn(&[u8]) -> Vec<u8>) -> bool {
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

fn encode_to_query_string(query: &[(String, String)]) -> String {
    let metacharacters = ['&', '='];

    query
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                encode_meta(key, &metacharacters),
                encode_meta(value, &metacharacters)
            )
        })
        .collect::<Vec<String>>()
        .join("&")
}

pub fn parse_query_string(str: &str) -> Vec<(String, String)> {
    str.split_terminator('&')
        .fold(Vec::new(), |mut acc, query| {
            if let Some((key, value)) = query.split_once('=') {
                acc.push((decode_meta(&key), decode_meta(&value)));
                acc
            } else {
                panic!("Invalid query string format")
            }
        })
}

fn encode_meta(str: &str, meta: &[char]) -> String {
    str.chars()
        .flat_map(|c| {
            if meta.contains(&c) {
                format!("%{}", util::bytes_to_hex(&[c as u8]))
                    .chars()
                    .collect::<Vec<char>>()
            } else {
                vec![c]
            }
        })
        .collect()
}

fn decode_meta(query: &str) -> String {
    let mut decoded = String::new();
    let mut i_prev = 0;
    for (i, _) in query.match_indices('%') {
        decoded.push_str(&query[i_prev..i]);
        decoded.push(util::hex_to_bytes(&query[i + 1..=i + 2])[0] as char);
        i_prev = i + 3;
    }
    decoded.push_str(&query[i_prev..]);
    decoded
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
