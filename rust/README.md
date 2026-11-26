# vorn (Rust)

> **Experimental research cipher. Not reviewed by third parties. Do not use it to protect real
> secrets.** For real use, take `aes-gcm` or `chacha20poly1305` from the RustCrypto project.

**Vorn-2** is an authenticated cipher (AEAD): a duplex sponge over a 512-bit ARX permutation
with prime-hopping round constants. This crate has **zero dependencies**, forbids `unsafe`, and
produces results identical to the Python and JavaScript implementations.

- Project, status, roadmap: <https://github.com/LowLeery/vorn>
- Specification and test vectors: <https://github.com/LowLeery/vorn/blob/main/SPEC.md>
- Analysis so far and what is still missing: <https://github.com/LowLeery/vorn/blob/main/ANALYSIS.md>
- **Cryptanalysis is invited**: please open an issue with anything you find.

## Password mode

```toml
[dependencies]
vorn = "0.2"
```

```rust
use vorn::password::{decrypt, encrypt, Params};

fn main() -> Result<(), vorn::Error> {
    let blob = encrypt(b"hello", b"correct-horse-battery-staple", b"", Params::default())?;
    let text = decrypt(&blob, b"correct-horse-battery-staple", b"")?;
    assert_eq!(text, b"hello");
    Ok(())
}
```

- The container is byte-for-byte compatible with the Python and JavaScript packages.
- The key comes from scrypt (default `n = 2^16, r = 8, p = 1`, 64 MiB, about 0.2 s). The scrypt
  and SHA-256 code is written in this crate, so there are no dependencies; it is checked against
  Python's `hashlib` on shared vectors, but it is **not** an audited KDF library.
- `password::encrypt` draws salt and nonce from `/dev/urandom` (Unix-like systems). On other
  platforms use `password::encrypt_with_randomness` with salt and nonce from your own CSPRNG.
  Never reuse a salt or nonce.

## Raw AEAD

```rust
use vorn::{seal, unseal};

fn main() -> Result<(), vorn::Error> {
    let key = [7u8; 32];    // use a real random 32-byte key
    let nonce = [9u8; 16];  // never reuse a (key, nonce) pair

    let sealed = seal(&key, &nonce, b"payload", b"header"); // ciphertext || 16-byte tag
    let opened = unseal(&key, &nonce, &sealed, b"header")?; // Err if anything was changed
    assert_eq!(opened, b"payload");
    Ok(())
}
```

Also exported: `permute` / `permute_rounds` (the Vorn-P permutation, reduced rounds for analysis)
and the constants.

## Performance and limits

About 100 MB/s in release mode on a single core. Not hardened against side channels (the
scrypt code is not constant-time either), no zeroization of secrets.

## License

MIT
