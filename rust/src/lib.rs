//! # Vorn-2
//!
//! An experimental duplex-sponge AEAD built on a 512-bit ARX permutation (**Vorn-P**) whose
//! round constants come from the square roots of primes and "hop" between state lanes
//! according to the prime.
//!
//! **EXPERIMENTAL.** Vorn-2 has not been reviewed by third parties. Do not use it to protect
//! real secrets; use a standard AEAD (AES-GCM, ChaCha20-Poly1305) instead. This crate is not
//! constant-time hardened and does not zeroize memory.
//!
//! Specification and test vectors: <https://github.com/LowLeery/vorn/blob/main/SPEC.md>
//!
//! ```
//! let key = [7u8; 32];
//! let nonce = [9u8; 16]; // never reuse a (key, nonce) pair
//! let sealed = vorn::seal(&key, &nonce, b"payload", b"header");
//! let opened = vorn::unseal(&key, &nonce, &sealed, b"header").unwrap();
//! assert_eq!(opened, b"payload");
//! ```
#![forbid(unsafe_code)]

use std::fmt;

/// Key length in bytes.
pub const KEY_LEN: usize = 32;
/// Nonce length in bytes.
pub const NONCE_LEN: usize = 16;
/// Authentication tag length in bytes.
pub const TAG_LEN: usize = 16;
/// State length in bytes (16 little-endian 32-bit words).
pub const STATE_LEN: usize = 64;
/// Full number of rounds of Vorn-P.
pub const ROUNDS: usize = 20;

const RATE: usize = 32;
const LABEL: &[u8; 16] = b"Vorn-2 AEAD v0.2";

const PRIMES: [u32; ROUNDS] = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
];

/// First 32 fractional bits of sqrt(p), computed as `isqrt(p << 64) mod 2^32`.
const fn round_constant(p: u32) -> u32 {
    let n = (p as u128) << 64;
    let mut x: u128 = 0;
    let mut bit: u128 = 1 << 40;
    while bit > 0 {
        let t = x | bit;
        if t * t <= n {
            x = t;
        }
        bit >>= 1;
    }
    x as u32
}

const fn round_constants() -> [u32; ROUNDS] {
    let mut out = [0u32; ROUNDS];
    let mut i = 0;
    while i < ROUNDS {
        out[i] = round_constant(PRIMES[i]);
        i += 1;
    }
    out
}

/// Round constants of Vorn-P (the first four equal the SHA-256 initial hash words).
pub const ROUND_CONSTANTS: [u32; ROUNDS] = round_constants();

const COLUMNS: [[usize; 4]; 4] = [[0, 4, 8, 12], [1, 5, 9, 13], [2, 6, 10, 14], [3, 7, 11, 15]];
const DIAGONALS: [[usize; 4]; 4] = [[0, 5, 10, 15], [1, 6, 11, 12], [2, 7, 8, 13], [3, 4, 9, 14]];

/// Errors returned by [`unseal`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The input is too short to contain a tag.
    Malformed,
    /// Wrong key, wrong nonce, wrong associated data, or modified ciphertext.
    Authentication,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed => f.write_str("malformed ciphertext"),
            Error::Authentication => {
                f.write_str("authentication failed: wrong key or modified data")
            }
        }
    }
}

impl std::error::Error for Error {}

/// Applies the full 20-round Vorn-P permutation to a 64-byte state in place.
pub fn permute(state: &mut [u8; STATE_LEN]) {
    permute_rounds(state, ROUNDS);
}

/// Vorn-P with a reduced number of rounds (1..=20). For analysis only.
pub fn permute_rounds(state: &mut [u8; STATE_LEN], rounds: usize) {
    assert!((1..=ROUNDS).contains(&rounds), "rounds out of range");
    let mut s = [0u32; 16];
    for (i, w) in s.iter_mut().enumerate() {
        *w = u32::from_le_bytes([
            state[4 * i],
            state[4 * i + 1],
            state[4 * i + 2],
            state[4 * i + 3],
        ]);
    }
    for r in 0..rounds {
        s[(PRIMES[r] % 16) as usize] ^= ROUND_CONSTANTS[r];
        let quads = if r & 1 == 1 { &DIAGONALS } else { &COLUMNS };
        for &[a, b, c, d] in quads {
            let (mut x, mut y, mut z, mut w) = (s[a], s[b], s[c], s[d]);
            x = x.wrapping_add(y);
            w = (w ^ x).rotate_left(16);
            z = z.wrapping_add(w);
            y = (y ^ z).rotate_left(12);
            x = x.wrapping_add(y);
            w = (w ^ x).rotate_left(8);
            z = z.wrapping_add(w);
            y = (y ^ z).rotate_left(7);
            s[a] = x;
            s[b] = y;
            s[c] = z;
            s[d] = w;
        }
    }
    for (i, w) in s.iter().enumerate() {
        state[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
}

fn run(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    data: &[u8],
    decrypting: bool,
) -> (Vec<u8>, [u8; TAG_LEN]) {
    let mut st = [0u8; STATE_LEN];
    st[..16].copy_from_slice(LABEL);
    st[16..32].copy_from_slice(nonce);
    st[32..].copy_from_slice(key);
    permute(&mut st);

    // associated data, always followed by one padded block (pad10*)
    let mut chunks = aad.chunks_exact(RATE);
    for block in &mut chunks {
        for (s, b) in st.iter_mut().zip(block) {
            *s ^= b;
        }
        permute(&mut st);
    }
    let rem = chunks.remainder();
    for (s, b) in st.iter_mut().zip(rem) {
        *s ^= b;
    }
    st[rem.len()] ^= 0x80;
    permute(&mut st);

    st[STATE_LEN - 1] ^= 0x01; // domain separation: associated data -> message

    let mut out = Vec::with_capacity(data.len());
    let mut chunks = data.chunks_exact(RATE);
    for block in &mut chunks {
        for (j, &b) in block.iter().enumerate() {
            let o = b ^ st[j];
            st[j] = if decrypting { b } else { o }; // the rate is overwritten with ciphertext
            out.push(o);
        }
        permute(&mut st);
    }
    let rem = chunks.remainder();
    for (j, &b) in rem.iter().enumerate() {
        let o = b ^ st[j];
        st[j] = if decrypting { b } else { o };
        out.push(o);
    }
    st[rem.len()] ^= 0x80;

    // finalisation: the key goes into the capacity again, the tag is read from the last 16 bytes
    for (s, k) in st[RATE..].iter_mut().zip(key) {
        *s ^= k;
    }
    permute(&mut st);
    let mut tag = [0u8; TAG_LEN];
    for (j, t) in tag.iter_mut().enumerate() {
        *t = st[48 + j] ^ key[16 + j];
    }
    (out, tag)
}

/// Encrypts `plaintext` and returns `ciphertext || 16-byte tag`.
///
/// `aad` is authenticated but not encrypted. **Never reuse a `(key, nonce)` pair.**
pub fn seal(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
    let (mut out, tag) = run(key, nonce, aad, plaintext, false);
    out.extend_from_slice(&tag);
    out
}

/// Verifies and decrypts the output of [`seal`]. No plaintext is returned if the tag is wrong.
pub fn unseal(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    sealed: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    if sealed.len() < TAG_LEN {
        return Err(Error::Malformed);
    }
    let (ct, tag) = sealed.split_at(sealed.len() - TAG_LEN);
    let (pt, expected) = run(key, nonce, aad, ct, true);
    let mut diff = 0u8;
    for (a, b) in tag.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    if diff == 0 {
        Ok(pt)
    } else {
        Err(Error::Authentication)
    }
}
