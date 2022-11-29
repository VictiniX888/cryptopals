/* ======== MERSENNE TWISTER ======== */
const W: usize = 32;
const N: usize = 624;
const M: usize = 397;
const R: usize = 31;
const A: u32 = 0x9908B0DF;
const U: usize = 11;
const D: u32 = 0xFFFFFFFF;
const S: usize = 7;
const B: u32 = 0x9D2C5680;
const T: usize = 15;
const C: u32 = 0xEFC60000;
const L: usize = 18;
const F: u32 = 1812433253;

const LOWER_MASK: u32 = (1 << R) - 1;
const UPPER_MASK: u32 = !LOWER_MASK;

pub struct MT19937 {
    state: [u32; N],
    index: usize,
}

impl MT19937 {
    pub fn new(seed: u32) -> MT19937 {
        let mut state = [seed.into(); N];
        for i in 1..N {
            state[i] = F
                .wrapping_mul(state[i - 1] ^ (state[i - 1] >> (W - 2)))
                .wrapping_add(i as u32);
        }

        MT19937 { state, index: N }
    }

    fn extract_number(&mut self) -> u32 {
        if self.index >= N {
            self.twist();
        }

        let mut y = self.state[self.index];
        y ^= (y >> U) & D;
        y ^= (y << S) & B;
        y ^= (y << T) & C;
        y ^= y >> L;

        self.index += 1;

        y
    }

    fn twist(&mut self) {
        for i in 0..N {
            let x = (self.state[i] & UPPER_MASK) | (self.state[(i + 1) % N] & LOWER_MASK);
            let mut x_a = x >> 1;
            if x % 2 != 0 {
                x_a ^= A;
            }
            self.state[i] = self.state[(i + M) % N] ^ x_a;
        }
        self.index = 0;
    }
}

impl Iterator for MT19937 {
    type Item = u32;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.extract_number())
    }
}
