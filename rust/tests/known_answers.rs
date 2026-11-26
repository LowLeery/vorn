mod vectors;

use vorn::{
    permute, permute_rounds, seal, unseal, Error, KEY_LEN, NONCE_LEN, ROUND_CONSTANTS, STATE_LEN,
    TAG_LEN,
};

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Small deterministic generator so the tests need no dependencies.
struct Xorshift(u64);
impl Xorshift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() >> 24) as u8).collect()
    }
}

#[test]
fn round_constants_are_sha256_style() {
    assert_eq!(
        &ROUND_CONSTANTS[..4],
        &[0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a]
    );
}

#[test]
fn permutation_known_answer() {
    let mut st = [0u8; STATE_LEN];
    permute(&mut st);
    assert_eq!(hex(&st), vectors::PERMUTATION_ZERO_STATE);
}

#[test]
fn reduced_rounds_differ_and_full_equals_default() {
    let mut a = [0u8; STATE_LEN];
    let mut b = [0u8; STATE_LEN];
    permute(&mut a);
    permute_rounds(&mut b, 20);
    assert_eq!(a, b);
    let mut c = [0u8; STATE_LEN];
    permute_rounds(&mut c, 19);
    assert_ne!(a, c);
}

#[test]
fn aead_known_answers() {
    for (key, nonce, aad, pt, out) in vectors::AEAD_VECTORS {
        let key: [u8; KEY_LEN] = unhex(key).try_into().unwrap();
        let nonce: [u8; NONCE_LEN] = unhex(nonce).try_into().unwrap();
        let (aad, pt, out) = (unhex(aad), unhex(pt), unhex(out));
        assert_eq!(seal(&key, &nonce, &pt, &aad), out);
        assert_eq!(unseal(&key, &nonce, &out, &aad).unwrap(), pt);
    }
}

fn keys(rng: &mut Xorshift) -> ([u8; KEY_LEN], [u8; NONCE_LEN]) {
    (
        rng.bytes(KEY_LEN).try_into().unwrap(),
        rng.bytes(NONCE_LEN).try_into().unwrap(),
    )
}

#[test]
fn roundtrip_and_lengths() {
    let mut rng = Xorshift(0x1234_5678_9abc_def1);
    let (key, nonce) = keys(&mut rng);
    for n in [0usize, 1, 31, 32, 33, 64, 65, 1000] {
        for ad_len in [0usize, 1, 32, 33] {
            let pt = rng.bytes(n);
            let aad = rng.bytes(ad_len);
            let sealed = seal(&key, &nonce, &pt, &aad);
            assert_eq!(sealed.len(), n + TAG_LEN);
            assert_eq!(unseal(&key, &nonce, &sealed, &aad).unwrap(), pt);
        }
    }
}

#[test]
fn every_single_bit_flip_is_rejected() {
    let mut rng = Xorshift(42);
    let (key, nonce) = keys(&mut rng);
    let sealed = seal(&key, &nonce, &rng.bytes(70), b"aad");
    for i in 0..sealed.len() {
        for bit in [0u8, 7] {
            let mut bad = sealed.clone();
            bad[i] ^= 1 << bit;
            assert_eq!(
                unseal(&key, &nonce, &bad, b"aad"),
                Err(Error::Authentication)
            );
        }
    }
}

#[test]
fn binds_aad_key_nonce_and_rejects_truncation() {
    let mut rng = Xorshift(7);
    let (key, nonce) = keys(&mut rng);
    let sealed = seal(&key, &nonce, b"payload", b"aad");
    assert_eq!(
        unseal(&key, &nonce, &sealed, b"other"),
        Err(Error::Authentication)
    );
    let (key2, nonce2) = keys(&mut rng);
    assert_eq!(
        unseal(&key2, &nonce, &sealed, b"aad"),
        Err(Error::Authentication)
    );
    assert_eq!(
        unseal(&key, &nonce2, &sealed, b"aad"),
        Err(Error::Authentication)
    );
    assert_eq!(
        unseal(&key, &nonce, &sealed[..sealed.len() - 1], b"aad"),
        Err(Error::Authentication)
    );
    assert_eq!(
        unseal(&key, &nonce, &sealed[1..], b"aad"),
        Err(Error::Authentication)
    );
    assert_eq!(
        unseal(&key, &nonce, &sealed[..15], b"aad"),
        Err(Error::Malformed)
    );
    assert_eq!(unseal(&key, &nonce, &[], b"aad"), Err(Error::Malformed));
}

#[test]
fn ad_and_message_boundary_is_unambiguous() {
    let (key, nonce) = ([3u8; KEY_LEN], [4u8; NONCE_LEN]);
    let a = seal(&key, &nonce, b"BBBB", b"AAAA");
    let b = seal(&key, &nonce, b"AAAABBBB", b"");
    let c = seal(&key, &nonce, b"", b"AAAABBBB");
    assert!(a != b && b != c && a != c);
}

#[test]
fn large_message() {
    let mut rng = Xorshift(99);
    let (key, nonce) = keys(&mut rng);
    let data = rng.bytes(300_000);
    let sealed = seal(&key, &nonce, &data, b"");
    assert_eq!(unseal(&key, &nonce, &sealed, b"").unwrap(), data);
}
