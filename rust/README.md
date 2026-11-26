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

## Usage

```toml
[dependencies]
vorn = "0.2"
```

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

`seal` and `unseal` are the whole API, plus `permute` / `permute_rounds` (the Vorn-P
permutation, reduced rounds for analysis) and the constants. The password container (scrypt)
is available in the Python and JavaScript packages and is **not** part of this crate yet.

## Performance and limits

About 100 MB/s in release mode on a single core. Not hardened against side channels, no
zeroization of secrets.

## License

MIT
