use crate::util;

pub fn calculate_edit_distance(b1: &[u8], b2: &[u8]) -> usize {
    b1.iter()
        .flat_map(|&b| util::byte_to_binary(b))
        .zip(b2.iter().flat_map(|&b| util::byte_to_binary(b)))
        .filter(|(b1, b2)| b1 != b2)
        .count()
}

// Using Kasiski examination
pub fn find_keysize_candidates(encoded: &[u8]) -> Vec<usize> {
    let mut keysizes: Vec<(usize, f64)> = (2..=40)
        .map(|size| {
            let mut edit_distance = 0;
            let blocks = encoded.len() / size;
            for i in 1..blocks {
                edit_distance +=
                    calculate_edit_distance(&encoded[..size], &encoded[size * i..size * (i + 1)])
            }
            (size, edit_distance as f64 / blocks as f64 / size as f64)
        })
        .collect();
    keysizes.sort_by(|(_, d1), (_, d2)| d1.partial_cmp(d2).unwrap());

    keysizes.iter().map(|&(size, _)| size).collect()
}

/* ============ XOR ============ */
pub struct RepeatingXORDecryptResult {
    pub key: Vec<u8>,
    pub message: Vec<u8>,
}

pub fn decrypt_repeating_key_xor(msg: &[u8], keysize: usize) -> RepeatingXORDecryptResult {
    let mut transposed: Vec<Vec<u8>> = vec![vec![]; keysize];

    for (i, &b) in msg.iter().enumerate() {
        transposed[i % keysize].push(b);
    }

    let key: Vec<u8> = transposed
        .iter()
        .map(|column| decrypt_single_byte_xor(column).unwrap().key)
        .collect();

    let message = repeating_key_xor(msg, &key);

    RepeatingXORDecryptResult { key, message }
}

pub fn repeating_key_xor(msg: &[u8], key: &[u8]) -> Vec<u8> {
    let key: Vec<u8> = vec![key.to_vec(); (msg.len() - 1) / key.len() + 1]
        .into_iter()
        .flatten()
        .take(msg.len())
        .collect();

    xor(msg, &key)
}

#[derive(Clone, Debug)]
pub struct XORDecryptResult {
    pub key: u8,
    pub message: Vec<u8>,
}

pub fn detect_single_byte_xor(encrypted_messages: &Vec<Vec<u8>>) -> Option<XORDecryptResult> {
    let freqs = util::generate_frequency_map();

    let decrypted = encrypted_messages
        .iter()
        .filter_map(|encrypted| decrypt_single_byte_xor(encrypted))
        .collect::<Vec<XORDecryptResult>>();

    let res = decrypted.iter().max_by(|a, b| {
        util::calculate_monogram_fitness(&a.message, &freqs)
            .partial_cmp(&util::calculate_monogram_fitness(&b.message, &freqs))
            .unwrap()
    });

    res.cloned()
}

// Unused
fn decrypt_single_byte_xor_options(encrypted: &[u8]) -> Vec<XORDecryptResult> {
    let freqs = util::generate_frequency_map();

    let mut decrypted: Vec<(u8, Vec<u8>)> = (u8::MIN..=u8::MAX)
        .map(|key| {
            let result = single_byte_xor(encrypted, key);
            (key, result) // tuple
        })
        //.filter(|(_, res)| res.iter().all(|&b| (b >= b' ' && b < 128) || b == b'\n'))
        .collect();

    decrypted.sort_by(|(_, str1), (_, str2)| {
        util::calculate_monogram_fitness(str1, &freqs)
            .partial_cmp(&util::calculate_monogram_fitness(str2, &freqs))
            .unwrap()
    });

    decrypted.reverse();

    decrypted
        .iter()
        .take(3)
        .map(|(key, res)| XORDecryptResult {
            key: *key,
            message: res.clone(),
        })
        .collect()
}

pub fn decrypt_single_byte_xor(encrypted: &[u8]) -> Option<XORDecryptResult> {
    let freqs = util::generate_frequency_map();

    let decrypted: Vec<(u8, Vec<u8>)> = (u8::MIN..=u8::MAX)
        .map(|key| {
            let result = single_byte_xor(encrypted, key);
            (key, result) // tuple
        })
        //.filter(|(_, res)| res.iter().all(|&b| (b >= b' ' && b < 128) || b == b'\n'))
        .collect();

    let res = decrypted.iter().max_by(|(_, str1), (_, str2)| {
        util::calculate_monogram_fitness(str1, &freqs)
            .partial_cmp(&util::calculate_monogram_fitness(str2, &freqs))
            .unwrap()
    });

    res.cloned()
        .map(|(key, message)| XORDecryptResult { key, message })

    // decrypted
    //     .iter()
    //     .take(5)
    //     .map(|decrypted| XORDecryptResult {
    //         key: decrypted.0,
    //         message: decrypted.1.clone(),
    //     })
    //     .collect()
}

pub fn single_byte_xor(msg: &[u8], key: u8) -> Vec<u8> {
    xor(msg, &vec![key; msg.len()])
}

// XORs each byte in two equal length byte arrays
// Additional bytes will be discarded
pub fn xor(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    assert!(b1.len() == b2.len());

    b1.iter().zip(b2.iter()).map(|(b1, b2)| b1 ^ b2).collect()
}
