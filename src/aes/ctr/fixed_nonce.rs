use crate::{aes, util, xor};
use rand::{thread_rng, Rng};

pub fn decrypt_fixed_nonce_ctr_statistically(ciphertexts: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let min_len = ciphertexts.iter().map(|bytes| bytes.len()).min().unwrap();

    let concat_ciphertext: Vec<u8> = ciphertexts
        .iter()
        .flat_map(|bytes| (&bytes[..min_len]).to_vec())
        .collect();

    let res = xor::decrypt_repeating_key_xor(&concat_ciphertext, min_len);

    res.message
        .chunks(min_len)
        .map(|bytes| bytes.to_vec())
        .collect()
}

// The plaintext guessed is hardcoded for this specific challenge
pub fn decrypt_fixed_nonce_ctr_substitution() {
    let plaintext = "SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
VG8gcGxlYXNlIGEgY29tcGFuaW9u
QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
U2hlIHJvZGUgdG8gaGFycmllcnM/
VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
SW4gdGhlIGNhc3VhbCBjb21lZHk7
SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
VHJhbnNmb3JtZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=";

    let plaintexts: Vec<Vec<u8>> = plaintext
        .split_terminator('\n')
        .map(|str| util::base64_to_bytes(str))
        .collect();

    let nonce = 0u64.to_le_bytes();
    let ciphertexts = encrypt_fixed_nonce_ctr(&plaintexts, &nonce);

    for ciphertext in ciphertexts.iter() {
        for b in ciphertext {
            print!("{:>4}", b);
        }
        print!("{}", '\n');
    }

    println!();

    let guessed_plaintext = b"He, too, has been changed in his turn.";

    let guessed_keystream = xor::xor(
        &ciphertexts[37][..guessed_plaintext.len()],
        guessed_plaintext,
    );

    let guessed_plaintexts: Vec<String> = ciphertexts
        .iter()
        .map(|bytes| {
            let len = guessed_keystream.len().min(bytes.len());
            xor::xor(&bytes[..len], &guessed_keystream[..len])
        })
        .map(|bytes| util::bytes_to_ascii(&bytes))
        .collect();

    for (i, guess) in guessed_plaintexts.iter().enumerate() {
        println!("{:>2} {}", i, guess);
    }
}

pub fn encrypt_fixed_nonce_ctr(plaintexts: &[Vec<u8>], nonce: &[u8]) -> Vec<Vec<u8>> {
    let key: [u8; 16] = thread_rng().gen();
    assert!(nonce.len() == 8);

    plaintexts
        .iter()
        .map(|bytes| aes::ctr::encrypt_aes_ctr(bytes, &key, nonce))
        .collect()
}
