//! Minimal SHA-256 and HMAC-SHA-256 (FIPS 180-4, RFC 2104), only what scrypt needs.
//!
//! The round constants are computed at compile time from the cube roots of the first 64
//! primes, and the initial state from the square roots of the first 8 primes.

const fn first_primes<const N: usize>() -> [u32; N] {
    let mut out = [0u32; N];
    let mut count = 0;
    let mut n = 2u32;
    while count < N {
        let mut is_prime = true;
        let mut d = 2u32;
        while d * d <= n {
            if n % d == 0 {
                is_prime = false;
                break;
            }
            d += 1;
        }
        if is_prime {
            out[count] = n;
            count += 1;
        }
        n += 1;
    }
    out
}

/// First 32 fractional bits of the cube root of `p`.
const fn cube_root_frac(p: u32) -> u32 {
    let n = (p as u128) << 96;
    let mut x: u128 = 0;
    let mut bit: u128 = 1 << 36;
    while bit > 0 {
        let t = x | bit;
        if t * t * t <= n {
            x = t;
        }
        bit >>= 1;
    }
    x as u32
}

const fn k_table() -> [u32; 64] {
    let primes = first_primes::<64>();
    let mut out = [0u32; 64];
    let mut i = 0;
    while i < 64 {
        out[i] = cube_root_frac(primes[i]);
        i += 1;
    }
    out
}

const fn h0() -> [u32; 8] {
    let primes = first_primes::<8>();
    let mut out = [0u32; 8];
    let mut i = 0;
    while i < 8 {
        out[i] = crate::round_constant(primes[i]);
        i += 1;
    }
    out
}

const K: [u32; 64] = k_table();
const H0: [u32; 8] = h0();
const BLOCK: usize = 64;

fn compress(h: &mut [u32; 8], block: &[u8]) {
    let mut w = [0u32; 64];
    for (i, word) in w.iter_mut().take(16).enumerate() {
        *word = u32::from_be_bytes([
            block[4 * i],
            block[4 * i + 1],
            block[4 * i + 2],
            block[4 * i + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh] = *h;
    for i in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let t1 = hh
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(K[i])
            .wrapping_add(w[i]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = s0.wrapping_add(maj);
        hh = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (state, v) in h.iter_mut().zip([a, b, c, d, e, f, g, hh]) {
        *state = state.wrapping_add(v);
    }
}

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = H0;
    let mut chunks = data.chunks_exact(BLOCK);
    for block in &mut chunks {
        compress(&mut h, block);
    }
    let rem = chunks.remainder();
    let mut tail = [0u8; 2 * BLOCK];
    tail[..rem.len()].copy_from_slice(rem);
    tail[rem.len()] = 0x80;
    let tail_len = if rem.len() + 1 + 8 <= BLOCK {
        BLOCK
    } else {
        2 * BLOCK
    };
    let bit_len = (data.len() as u64).wrapping_mul(8);
    tail[tail_len - 8..tail_len].copy_from_slice(&bit_len.to_be_bytes());
    for block in tail[..tail_len].chunks_exact(BLOCK) {
        compress(&mut h, block);
    }
    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

pub(crate) fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k = [0u8; BLOCK];
    if key.len() > BLOCK {
        k[..32].copy_from_slice(&sha256(key));
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = Vec::with_capacity(BLOCK + msg.len());
    inner.extend(k.iter().map(|b| b ^ 0x36));
    inner.extend_from_slice(msg);
    let inner_hash = sha256(&inner);
    let mut outer = Vec::with_capacity(BLOCK + 32);
    outer.extend(k.iter().map(|b| b ^ 0x5c));
    outer.extend_from_slice(&inner_hash);
    sha256(&outer)
}

#[cfg(test)]
mod tests {
    use super::*;

    mod vectors {
        include!("../tests/vectors.rs");
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn constants_match_fips_180_4() {
        assert_eq!(H0[0], 0x6a09e667);
        assert_eq!(H0[7], 0x5be0cd19);
        assert_eq!(K[0], 0x428a2f98);
        assert_eq!(K[1], 0x71374491);
        assert_eq!(K[63], 0xc67178f2);
    }

    #[test]
    fn sha256_matches_python_hashlib() {
        for (len, expected) in vectors::SHA256_VECTORS {
            let msg: Vec<u8> = (0..*len).map(|i| (i % 256) as u8).collect();
            assert_eq!(hex(&sha256(&msg)), *expected, "length {len}");
        }
    }

    #[test]
    fn hmac_matches_python_hmac() {
        for (key, msg, expected) in vectors::HMAC_VECTORS {
            assert_eq!(hex(&hmac_sha256(&unhex(key), &unhex(msg))), *expected);
        }
    }
}
