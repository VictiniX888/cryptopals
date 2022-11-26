pub mod cbc;
pub mod ecb;

use crate::util;
use rand::{distributions::Uniform, thread_rng, Rng};

/* ======== RANDOM AES MODE ======== */
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
        ecb::encrypt_aes_ecb(&bytes_modified, &key)
    } else {
        // Use CBC half the time
        print!("CBC: ");
        let mut iv = [0u8; 16];
        rng.fill(&mut iv);
        cbc::encrypt_aes_cbc(&bytes_modified, &key, &iv)
    };

    encrypted
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

pub fn strip_pkcs7(message: &[u8]) -> Result<Vec<u8>, String> {
    if validate_pkcs7(message) {
        Ok(Vec::from(
            &message[..message.len() - *(message.last().unwrap()) as usize],
        ))
    } else {
        Err("Invalid PKCS#7 padding".to_string())
    }
}

fn validate_pkcs7(message: &[u8]) -> bool {
    if message.last() == Some(&0) {
        return false;
    }

    if let Some(&padding) = message.last() {
        if message.len() >= padding.into() {
            return message
                .iter()
                .rev()
                .take(padding.into())
                .all(|&b| b == padding);
        }
    }

    false
}

fn encode_to_query_string(query: &[(String, String)], sep: char, middle: char) -> String {
    let metacharacters = [sep, middle];

    query
        .iter()
        .map(|(key, value)| {
            format!(
                "{}{}{}",
                encode_meta(key, &metacharacters),
                middle,
                encode_meta(value, &metacharacters)
            )
        })
        .collect::<Vec<String>>()
        .join(&sep.to_string())
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

pub fn encode_meta(str: &str, meta: &[char]) -> String {
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

pub fn decode_meta(query: &str) -> String {
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
