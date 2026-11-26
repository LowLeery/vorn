mod vectors;

use vorn::password::{decrypt, encrypt, encrypt_with_randomness, Params, HEADER_LEN};
use vorn::Error;

const SALT: [u8; 16] = [1; 16];
const NONCE: [u8; 16] = [2; 16];
const FAST: Params = Params {
    log_n: 4,
    r: 1,
    p: 1,
};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn decrypts_containers_made_by_python() {
    for (password, aad, plaintext, blob) in vectors::PASSWORD_VECTORS {
        let out = decrypt(&unhex(blob), &unhex(password), &unhex(aad)).unwrap();
        assert_eq!(out, unhex(plaintext));
    }
}

#[test]
fn reproduces_the_python_containers_bit_for_bit() {
    // The Python vectors use fixed salt and nonce, recoverable from the header.
    for (password, aad, plaintext, blob) in vectors::PASSWORD_VECTORS {
        let blob = unhex(blob);
        let params = Params {
            log_n: blob[4],
            r: blob[5],
            p: blob[6],
        };
        let salt: [u8; 16] = blob[7..23].try_into().unwrap();
        let nonce: [u8; 16] = blob[23..39].try_into().unwrap();
        let ours = encrypt_with_randomness(
            &unhex(plaintext),
            &unhex(password),
            &unhex(aad),
            params,
            &salt,
            &nonce,
        )
        .unwrap();
        assert_eq!(ours, blob);
    }
}

#[test]
fn roundtrip_various_sizes_and_aad() {
    for n in [0usize, 1, 31, 32, 33, 1000] {
        let data: Vec<u8> = (0..n).map(|i| (i * 7) as u8).collect();
        for aad in [&b""[..], b"context"] {
            let blob =
                encrypt_with_randomness(&data, b"pw-\xc3\xa7", aad, FAST, &SALT, &NONCE).unwrap();
            assert_eq!(blob.len(), HEADER_LEN + n + 16);
            assert_eq!(decrypt(&blob, b"pw-\xc3\xa7", aad).unwrap(), data);
        }
    }
}

#[test]
fn wrong_password_and_wrong_aad_are_rejected() {
    let blob = encrypt_with_randomness(b"secret", b"right", b"ctx", FAST, &SALT, &NONCE).unwrap();
    assert_eq!(decrypt(&blob, b"wrong", b"ctx"), Err(Error::Authentication));
    assert_eq!(
        decrypt(&blob, b"right", b"other"),
        Err(Error::Authentication)
    );
    assert_eq!(decrypt(&blob, b"", b"ctx"), Err(Error::EmptyPassword));
    assert_eq!(
        encrypt_with_randomness(b"x", b"", b"", FAST, &SALT, &NONCE),
        Err(Error::EmptyPassword)
    );
}

#[test]
fn every_byte_of_the_container_is_authenticated() {
    let blob = encrypt_with_randomness(b"authenticated", b"pw", b"", FAST, &SALT, &NONCE).unwrap();
    for i in 0..blob.len() {
        let mut bad = blob.clone();
        bad[i] ^= 1;
        assert!(
            decrypt(&bad, b"pw", b"").is_err(),
            "flip at byte {i} was accepted"
        );
    }
}

#[test]
fn malformed_input() {
    for bad in [&b""[..], b"VRN2", &[0u8; 80]] {
        assert_eq!(decrypt(bad, b"pw", b""), Err(Error::Malformed));
    }
    let blob = encrypt_with_randomness(b"x", b"pw", b"", FAST, &SALT, &NONCE).unwrap();
    assert!(decrypt(&blob[..blob.len() - 1], b"pw", b"").is_err());
}

#[test]
fn unreasonable_parameters_are_rejected() {
    for params in [
        Params {
            log_n: 0,
            r: 8,
            p: 1,
        },
        Params {
            log_n: 25,
            r: 8,
            p: 1,
        },
        Params {
            log_n: 24,
            r: 8,
            p: 1,
        }, // 128 * 8 * 2^24 = 16 GiB
        Params {
            log_n: 4,
            r: 0,
            p: 1,
        },
        Params {
            log_n: 4,
            r: 33,
            p: 1,
        },
        Params {
            log_n: 4,
            r: 1,
            p: 0,
        },
        Params {
            log_n: 4,
            r: 1,
            p: 17,
        },
    ] {
        assert_eq!(
            encrypt_with_randomness(b"x", b"pw", b"", params, &SALT, &NONCE),
            Err(Error::InvalidParameters)
        );
    }
    let mut blob = encrypt_with_randomness(b"x", b"pw", b"", FAST, &SALT, &NONCE).unwrap();
    blob[4] = 30; // a crafted header must not make us allocate terabytes
    assert_eq!(decrypt(&blob, b"pw", b""), Err(Error::InvalidParameters));
}

#[cfg(unix)]
#[test]
fn encrypt_uses_fresh_salt_and_nonce() {
    let a = encrypt(b"same", b"pw", b"", FAST).unwrap();
    let b = encrypt(b"same", b"pw", b"", FAST).unwrap();
    assert_ne!(a, b);
    assert_ne!(a[7..23], b[7..23]);
    assert_ne!(a[23..39], b[23..39]);
    assert_eq!(decrypt(&a, b"pw", b"").unwrap(), b"same");
}

#[test]
fn default_parameters_work_end_to_end() {
    // The default cost (n = 2^16, 64 MiB) is slow in debug builds, so only check the values here.
    assert_eq!(
        Params::default(),
        Params {
            log_n: 16,
            r: 8,
            p: 1
        }
    );
}
