use rand::{thread_rng, Rng};

use crate::util;

/* ======== CBC BITFLIPPING ATTACK ======== */
pub fn cbc_bitflipping_attack_admin() -> Vec<u8> {
    let userdata: String = ["a"; 16].join("");

    // Encode data
    let encoded = profile_for(
        "comment1=cooking%20MCs;userdata=",
        &userdata,
        ";comment2=%20like%20a%20pound%20of%20bacon",
    );
    println!("Original plaintext: {}", encoded);
    let encoded = util::ascii_to_bytes(&encoded);

    // Generate oracle functions
    let (encrypt, decrypt) = gen_aes_cbc_encrypt_decrypt_oracles();

    let mut ciphertext = encrypt(&encoded);
    println!("Original ciphertext: {}", util::bytes_to_hex(&ciphertext));

    // Target bytes must be <= 16 bytes
    let target_bytes = b";admin=true;a=";
    let target_block = 3;

    // Flip bits to get admin=true
    for (i, &target_byte) in target_bytes.iter().enumerate() {
        let original_byte = encoded[target_block * 16 + i];
        let diff_bits = original_byte ^ target_byte;
        *ciphertext.get_mut((target_block - 1) * 16 + i).unwrap() ^= diff_bits;
    }

    let plaintext = decrypt(&ciphertext).unwrap();

    println!("Modified ciphertext: {}", util::bytes_to_hex(&ciphertext));
    println!("Is admin: {}", is_admin(&plaintext));

    plaintext
}

fn gen_aes_cbc_encrypt_decrypt_oracles() -> (
    impl Fn(&[u8]) -> Vec<u8>,
    impl Fn(&[u8]) -> Result<Vec<u8>, String>,
) {
    let mut rng = thread_rng();
    let key: [u8; 16] = rng.gen();
    let iv: [u8; 16] = rng.gen();

    (
        move |plaintext: &[u8]| super::encrypt_aes_cbc(plaintext, &key, &iv),
        move |ciphertext: &[u8]| super::decrypt_aes_cbc(ciphertext, &key, &iv),
    )
}

fn is_admin(bytes: &[u8]) -> bool {
    util::bytes_to_ascii(bytes).contains(";admin=true;")
}

fn profile_for(prefix: &str, userdata: &str, suffix: &str) -> String {
    let mut profile = String::new();
    profile.push_str(prefix);
    profile.push_str(&super::super::encode_meta(userdata, &[';', '=']));
    profile.push_str(suffix);

    profile
}
