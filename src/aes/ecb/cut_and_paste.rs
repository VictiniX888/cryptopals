use crate::util;
use rand::{thread_rng, Rng};

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
        move |plaintext: &[u8]| super::encrypt_aes_ecb(plaintext, &key),
        move |ciphertext: &[u8]| super::decrypt_aes_ecb(ciphertext, &key),
    )
}

pub fn profile_for(email: &str) -> String {
    let profile = [
        ("email".to_string(), email.to_string()),
        ("uid".to_string(), 10u8.to_string()),
        ("role".to_string(), "user".to_string()),
    ];

    super::super::encode_to_query_string(&profile)
}
