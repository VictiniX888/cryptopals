use std::collections::HashMap;

/* ============ FREQUENCY ANALYSIS ============ */
pub fn generate_frequency_map() -> HashMap<char, f64> {
    let monograms = include_str!("../assets/english_monograms.txt");
    let mut freqs = monograms
        .split_terminator('\n')
        .map(|line| line.split_whitespace())
        .fold(HashMap::new(), |mut acc, mut line| {
            acc.insert(
                line.next().unwrap().to_lowercase().chars().next().unwrap(),
                str::parse::<f64>(line.next().unwrap()).unwrap(),
            );
            acc
        });

    let total: f64 = freqs.values().sum();
    for (_, val) in freqs.iter_mut() {
        *val = *val / total;
    }

    freqs
}

pub fn calculate_monogram_fitness(str: &[u8], freqs: &HashMap<char, f64>) -> f64 {
    str.iter().fold(0f64, |acc, &b| {
        let freq = freqs.get(&(b as char)).cloned().unwrap_or_else(|| {
            if b == b' ' {
                0.2 // approximate frequency of space
            } else {
                0.0000000001 // approximate frequency of other chars
            }
        });

        acc + freq.log10()
    })
}

// Unused, prefer monogram analysis for determining fitness of text
fn calculate_chi_squared(str: &[u8], freqs: &HashMap<char, f64>) -> f64 {
    let str_filtered: Vec<u8> = str
        .iter()
        .filter(|&&c| (c >= b'a' && c <= b'z') || (c >= b'A' && c <= b'Z'))
        .map(|&c| {
            if c >= b'A' && c <= b'Z' {
                c - b'A' + b'a'
            } else {
                c
            }
        })
        .collect();

    let counts = str_filtered.iter().fold(HashMap::new(), |mut acc, &c| {
        *acc.entry(c).or_insert(0) += 1;
        acc
    });

    freqs.iter().fold(0f64, |acc, (&c, freq)| {
        let c = c as u8;
        let expected_count = freq * str.len() as f64;
        let &count = counts.get(&c).unwrap_or(&0);
        let chi_square =
            (count as f64 - expected_count) * (count as f64 - expected_count) / expected_count;
        acc + chi_square
    })
}

/* ============ HEX ============ */
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    if hex.len() % 2 != 0 {
        panic!("Hex string does not have even length")
    }

    let half_bytes: Vec<u8> = hex
        .to_lowercase()
        .bytes()
        .map(|b| {
            if b >= 48 && b <= 57 {
                b - 48
            } else {
                b - 97 + 10
            }
        })
        .collect();

    half_bytes.chunks(2).map(|b| b[0] * 16 + b[1]).collect()
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .flat_map(|&b| {
            if b >= 16 {
                [int_to_hex(b / 16), int_to_hex(b % 16)]
            } else {
                ['0', int_to_hex(b)]
            }
        })
        .collect()
}

// Int must be unsigned and less 4 bits
fn int_to_hex(i: u8) -> char {
    if i <= 9 {
        char::from_digit(i.into(), 10).unwrap()
    } else if i <= 15 {
        char::from_u32((i - 10 + 97).into()).unwrap()
    } else {
        panic!("Cannot convert number greater than 16 to a single hex digit")
    }
}

/* ============ BASE64 ============ */
pub fn base64_to_bytes(base64: &str) -> Vec<u8> {
    assert!(base64.len() % 4 == 0);

    let binary: Vec<bool> = base64.chars().flat_map(base64_to_binary).collect();

    binary.chunks_exact(8).map(binary_to_byte).collect()
}

pub fn bytes_to_base64(bytes: &[u8]) -> String {
    let bits: Vec<bool> = bytes.iter().flat_map(|&b| byte_to_binary(b)).collect();
    let mut base64: String = bits.chunks(6).map(binary_to_base64).collect();
    while base64.len() % 4 != 0 {
        base64 += "=";
    }

    base64
}

fn base64_to_binary(c: char) -> Vec<bool> {
    if c == '=' {
        return vec![];
    }

    let byte = if c >= 'A' && c <= 'Z' {
        c as u8 - b'A'
    } else if c >= 'a' && c <= 'z' {
        c as u8 - b'a' + 26
    } else if c >= '0' && c <= '9' {
        c as u8 - b'0' + 52
    } else if c == '+' {
        62
    } else if c == '/' {
        63
    } else {
        panic!("Invalid base64 char")
    };

    byte_to_binary(byte).into_iter().skip(2).collect()
}

fn binary_to_base64(binary: &[bool]) -> char {
    let mut binary = binary.to_vec();
    while binary.len() < 6 {
        binary.push(false);
    }

    let mut scalar = 1;
    let mut c = 0;

    for &b in binary.iter().rev() {
        c += (b as u8) * scalar;
        scalar *= 2;
    }

    if c <= 25 {
        char::from_u32((b'A' + c).into()).unwrap()
    } else if c <= 51 {
        char::from_u32((b'a' + c - 26).into()).unwrap()
    } else if c <= 61 {
        char::from_u32((b'0' + c - 52).into()).unwrap()
    } else if c == 62 {
        '+'
    } else if c == 63 {
        '/'
    } else {
        panic!("Invalid binary string")
    }
}

/* ============ ASCII ============ */
pub fn bytes_to_ascii(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| b as char).collect()
}

pub fn ascii_to_bytes(ascii: &str) -> Vec<u8> {
    ascii.as_bytes().to_vec()
}

pub fn byte_to_binary(byte: u8) -> Vec<bool> {
    let mut exp = 128;
    let mut i = 0;
    let mut byte = byte;
    let mut binary = vec![false; 8];

    while byte > 0 {
        if byte >= exp {
            byte -= exp;
            binary[i] = true;
        }

        exp /= 2;
        i += 1;
    }

    binary
}

fn binary_to_byte(binary: &[bool]) -> u8 {
    assert!(binary.len() == 8);

    let mut scalar: u8 = 1;
    let mut byte = 0;
    for &b in binary.iter().rev() {
        if b {
            byte += scalar;
        }
        scalar = scalar.wrapping_mul(2);
    }

    byte
}
