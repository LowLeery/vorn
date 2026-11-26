//! Password-based encryption container (SPEC section 4), compatible with the Python and
//! JavaScript packages.
//!
//! ```text
//! "VRN2" | log2(n) | r | p | salt(16) | nonce(16) | ciphertext | tag(16)
//! ```
//!
//! The key is `scrypt(password, salt, n = 2^log_n, r, p)` (32 bytes). The whole header and any
//! extra associated data are authenticated. Decryption refuses scrypt settings outside
//! `1 <= log_n <= 24`, `1 <= r <= 32`, `1 <= p <= 16` or needing more than 512 MiB.
//!
//! ```
//! use vorn::password::{decrypt, encrypt_with_randomness, Params};
//!
//! // In real use take `salt` and `nonce` from a CSPRNG (or call `password::encrypt`).
//! let params = Params { log_n: 8, ..Params::default() }; // small cost, doc-test only
//! let blob = encrypt_with_randomness(b"hello", b"correct horse", b"", params, &[1; 16], &[2; 16]).unwrap();
//! assert_eq!(decrypt(&blob, b"correct horse", b"").unwrap(), b"hello");
//! ```

use crate::scrypt::scrypt32;
use crate::{seal, unseal, Error, KEY_LEN, NONCE_LEN};

/// Container magic bytes.
pub const MAGIC: &[u8; 4] = b"VRN2";
/// Salt length in bytes.
pub const SALT_LEN: usize = 16;
/// Header length: magic, three parameter bytes, salt, nonce.
pub const HEADER_LEN: usize = 4 + 3 + SALT_LEN + NONCE_LEN;

const MAX_SCRYPT_BYTES: u64 = 1 << 29;

/// scrypt cost parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Params {
    /// log2 of the scrypt `n` parameter (default 16, which uses 64 MiB).
    pub log_n: u8,
    /// scrypt block size `r` (default 8).
    pub r: u8,
    /// scrypt parallelism `p` (default 1).
    pub p: u8,
}

impl Default for Params {
    fn default() -> Self {
        Params {
            log_n: 16,
            r: 8,
            p: 1,
        }
    }
}

fn check_params(params: Params) -> Result<(), Error> {
    let Params { log_n, r, p } = params;
    if !(1..=24).contains(&log_n) || !(1..=32).contains(&r) || !(1..=16).contains(&p) {
        return Err(Error::InvalidParameters);
    }
    if 128u64 * u64::from(r) * (1u64 << log_n) > MAX_SCRYPT_BYTES {
        return Err(Error::InvalidParameters);
    }
    Ok(())
}

fn derive_key(password: &[u8], salt: &[u8], params: Params) -> Result<[u8; KEY_LEN], Error> {
    if password.is_empty() {
        return Err(Error::EmptyPassword);
    }
    Ok(scrypt32(
        password,
        salt,
        params.log_n,
        u32::from(params.r),
        u32::from(params.p),
    ))
}

fn associated_data(header: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(header.len() + aad.len());
    ad.extend_from_slice(header);
    ad.extend_from_slice(aad);
    ad
}

/// Encrypts with a password using caller-supplied randomness.
///
/// `salt` and `nonce` **must** come from a cryptographically secure random generator and must
/// never be reused with the same password. Prefer [`encrypt`] where it is available.
pub fn encrypt_with_randomness(
    data: &[u8],
    password: &[u8],
    aad: &[u8],
    params: Params,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, Error> {
    check_params(params)?;
    let key = derive_key(password, salt, params)?;
    let mut blob = Vec::with_capacity(HEADER_LEN + data.len() + crate::TAG_LEN);
    blob.extend_from_slice(MAGIC);
    blob.extend_from_slice(&[params.log_n, params.r, params.p]);
    blob.extend_from_slice(salt);
    blob.extend_from_slice(nonce);
    let sealed = seal(&key, nonce, data, &associated_data(&blob, aad));
    blob.extend_from_slice(&sealed);
    Ok(blob)
}

/// Fills `buf` from the operating system's random source (`/dev/urandom`).
///
/// Only available on Unix-like systems; elsewhere it returns [`Error::Randomness`], and you
/// should use [`encrypt_with_randomness`] with your own CSPRNG.
fn os_random(buf: &mut [u8]) -> Result<(), Error> {
    use std::io::Read;
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .map_err(|_| Error::Randomness)
}

/// Encrypts with a password, drawing salt and nonce from `/dev/urandom` (Unix-like systems).
pub fn encrypt(data: &[u8], password: &[u8], aad: &[u8], params: Params) -> Result<Vec<u8>, Error> {
    let mut salt = [0u8; SALT_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    os_random(&mut salt)?;
    os_random(&mut nonce)?;
    encrypt_with_randomness(data, password, aad, params, &salt, &nonce)
}

/// Decrypts the output of [`encrypt`] (or of the Python and JavaScript packages).
pub fn decrypt(blob: &[u8], password: &[u8], aad: &[u8]) -> Result<Vec<u8>, Error> {
    if blob.len() < HEADER_LEN + crate::TAG_LEN || &blob[..4] != MAGIC {
        return Err(Error::Malformed);
    }
    let params = Params {
        log_n: blob[4],
        r: blob[5],
        p: blob[6],
    };
    check_params(params)?;
    let (header, sealed) = blob.split_at(HEADER_LEN);
    let salt = &header[7..7 + SALT_LEN];
    let nonce: [u8; NONCE_LEN] = header[7 + SALT_LEN..]
        .try_into()
        .map_err(|_| Error::Malformed)?;
    let key = derive_key(password, salt, params)?;
    unseal(&key, &nonce, sealed, &associated_data(header, aad))
}
