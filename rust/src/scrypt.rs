//! Minimal scrypt (RFC 7914), included so that the password API needs no dependencies.
//!
//! Not a general-purpose KDF library: output length and parameters are limited to what the
//! Vorn password container uses. Checked against Python's `hashlib.scrypt`.

use crate::sha256::hmac_sha256;

/// PBKDF2-HMAC-SHA-256 with a single iteration (c = 1), as scrypt uses it.
fn pbkdf2_sha256_c1(password: &[u8], salt: &[u8], dk_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(dk_len + 32);
    let mut msg = Vec::with_capacity(salt.len() + 4);
    let mut block: u32 = 1;
    while out.len() < dk_len {
        msg.clear();
        msg.extend_from_slice(salt);
        msg.extend_from_slice(&block.to_be_bytes());
        out.extend_from_slice(&hmac_sha256(password, &msg));
        block += 1;
    }
    out.truncate(dk_len);
    out
}

fn salsa20_8(b: &mut [u32; 16]) {
    let mut x = *b;
    for _ in 0..4 {
        x[4] ^= x[0].wrapping_add(x[12]).rotate_left(7);
        x[8] ^= x[4].wrapping_add(x[0]).rotate_left(9);
        x[12] ^= x[8].wrapping_add(x[4]).rotate_left(13);
        x[0] ^= x[12].wrapping_add(x[8]).rotate_left(18);
        x[9] ^= x[5].wrapping_add(x[1]).rotate_left(7);
        x[13] ^= x[9].wrapping_add(x[5]).rotate_left(9);
        x[1] ^= x[13].wrapping_add(x[9]).rotate_left(13);
        x[5] ^= x[1].wrapping_add(x[13]).rotate_left(18);
        x[14] ^= x[10].wrapping_add(x[6]).rotate_left(7);
        x[2] ^= x[14].wrapping_add(x[10]).rotate_left(9);
        x[6] ^= x[2].wrapping_add(x[14]).rotate_left(13);
        x[10] ^= x[6].wrapping_add(x[2]).rotate_left(18);
        x[3] ^= x[15].wrapping_add(x[11]).rotate_left(7);
        x[7] ^= x[3].wrapping_add(x[15]).rotate_left(9);
        x[11] ^= x[7].wrapping_add(x[3]).rotate_left(13);
        x[15] ^= x[11].wrapping_add(x[7]).rotate_left(18);

        x[1] ^= x[0].wrapping_add(x[3]).rotate_left(7);
        x[2] ^= x[1].wrapping_add(x[0]).rotate_left(9);
        x[3] ^= x[2].wrapping_add(x[1]).rotate_left(13);
        x[0] ^= x[3].wrapping_add(x[2]).rotate_left(18);
        x[6] ^= x[5].wrapping_add(x[4]).rotate_left(7);
        x[7] ^= x[6].wrapping_add(x[5]).rotate_left(9);
        x[4] ^= x[7].wrapping_add(x[6]).rotate_left(13);
        x[5] ^= x[4].wrapping_add(x[7]).rotate_left(18);
        x[11] ^= x[10].wrapping_add(x[9]).rotate_left(7);
        x[8] ^= x[11].wrapping_add(x[10]).rotate_left(9);
        x[9] ^= x[8].wrapping_add(x[11]).rotate_left(13);
        x[10] ^= x[9].wrapping_add(x[8]).rotate_left(18);
        x[12] ^= x[15].wrapping_add(x[14]).rotate_left(7);
        x[13] ^= x[12].wrapping_add(x[15]).rotate_left(9);
        x[14] ^= x[13].wrapping_add(x[12]).rotate_left(13);
        x[15] ^= x[14].wrapping_add(x[13]).rotate_left(18);
    }
    for (v, add) in b.iter_mut().zip(x) {
        *v = v.wrapping_add(add);
    }
}

/// scryptBlockMix: `b` and `out` hold `2 * r` blocks of 16 words.
fn block_mix(b: &[u32], out: &mut [u32], r: usize) {
    let mut x = [0u32; 16];
    x.copy_from_slice(&b[(2 * r - 1) * 16..2 * r * 16]);
    for i in 0..2 * r {
        for (xv, bv) in x.iter_mut().zip(&b[i * 16..(i + 1) * 16]) {
            *xv ^= bv;
        }
        salsa20_8(&mut x);
        let dst = if i % 2 == 0 {
            (i / 2) * 16
        } else {
            (r + i / 2) * 16
        };
        out[dst..dst + 16].copy_from_slice(&x);
    }
}

/// scryptROMix on one block of `32 * r` words.
fn ro_mix(b: &mut [u32], n: usize, r: usize) {
    let len = 32 * r;
    let mut v = vec![0u32; len * n];
    let mut x = b.to_vec();
    let mut y = vec![0u32; len];
    for i in 0..n {
        v[i * len..(i + 1) * len].copy_from_slice(&x);
        block_mix(&x, &mut y, r);
        std::mem::swap(&mut x, &mut y);
    }
    for _ in 0..n {
        let j = (x[(2 * r - 1) * 16] as usize) & (n - 1);
        for (xv, vv) in x.iter_mut().zip(&v[j * len..(j + 1) * len]) {
            *xv ^= vv;
        }
        block_mix(&x, &mut y, r);
        std::mem::swap(&mut x, &mut y);
    }
    b.copy_from_slice(&x);
}

/// scrypt with a 32-byte output. `n = 2^log_n`; the caller must have validated the parameters.
pub(crate) fn scrypt32(password: &[u8], salt: &[u8], log_n: u8, r: u32, p: u32) -> [u8; 32] {
    let n = 1usize << log_n;
    let (r, p) = (r as usize, p as usize);
    let mut b = pbkdf2_sha256_c1(password, salt, 128 * r * p);
    for chunk in b.chunks_exact_mut(128 * r) {
        let mut words: Vec<u32> = chunk
            .chunks_exact(4)
            .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
            .collect();
        ro_mix(&mut words, n, r);
        for (dst, w) in chunk.chunks_exact_mut(4).zip(&words) {
            dst.copy_from_slice(&w.to_le_bytes());
        }
    }
    let dk = pbkdf2_sha256_c1(password, &b, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&dk);
    out
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
    fn scrypt_matches_python_hashlib() {
        for (pw, salt, log_n, r, p, expected) in vectors::SCRYPT_VECTORS {
            let dk = scrypt32(&unhex(pw), &unhex(salt), *log_n, *r, *p);
            assert_eq!(hex(&dk), *expected, "log_n={log_n} r={r} p={p}");
        }
    }
}
