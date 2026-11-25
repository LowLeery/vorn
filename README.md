# Vorn

> **Warning: experimental / educational.** Vorn is a custom cipher design. It has **not** been
> reviewed by cryptographers and must **not** be used to protect real secrets. For production use
> a vetted AEAD such as AES-GCM or ChaCha20-Poly1305 (e.g. via the `cryptography` package).

**Vorn** is a zero-dependency Python library that experiments with a symmetric cipher built from
dynamic prime-index hopping, alternating modular offsets, a keyed bit permutation, and
HMAC-SHA256 authentication (Encrypt-then-MAC).

## Installation

```bash
pip install vorn
```

## Usage

```python
from vorn import encrypt, decrypt, VornError

password = "correct-horse-battery-staple"
ciphertext = encrypt("Payload 257-ALPHA", password)

try:
    plaintext = decrypt(ciphertext, password).decode("utf-8")
    print(plaintext)
except VornError as e:
    print(f"Decryption error: {e}")
```

### Files

```python
from vorn import encrypt, decrypt

with open("archive.bin", "rb") as src:
    encoded = encrypt(src.read(), "file-encryption-key")

with open("archive.vorn", "w", encoding="ascii") as dst:
    dst.write(encoded)

with open("archive.vorn", "r", encoding="ascii") as src:
    restored = decrypt(src.read(), "file-encryption-key")
```

Note: the pure-Python implementation is slow and memory hungry, and ciphertext is about
24 characters per plaintext byte. It is meant for small payloads.

## Specification

### 1. Key derivation
A UTF-8 passphrase `P` and a random 128-bit nonce `N` are fed to **scrypt** (n=16384, r=8, p=1)
to produce 64 bytes: `K_enc (32 bytes, 24 used) || K_pbox (8 bytes) || K_mac (32 bytes)`.

From `K_enc` the following parameters are derived:
- `a`: one of 16, 24, 32, 40, 48, 56 (a multiple of 8).
- `b`: a modular base (3..19) that does not divide `a`.
- `c`: block period `a / x` with `x` in {1, 2, 4, 8}.
- `d`: polarity bit selecting the initial offset sign.
- `S0_fwd`, `S0_bwd`: initial chaining states (100..999) for the two passes.
- A keyed 16-element S-Box over nibbles.

### 2. Round function
Input bytes are split into nibbles and passed through the S-Box. For symbol `s_i` with previous
state `C_{i-1}` (`C_{-1} = S0`):

```
J_i     = a + (C_{i-1} mod 16)
p_i     = Prime[s_i + J_i]
R_i     = (a mod b) + (C_{i-1} mod b)
sigma_i = (-1)^(floor(i / c) + d)
C_i     = p_i + sigma_i * R_i
```

### 3. Diffusion
1. Forward pass over all nibbles using `S0_fwd`.
2. States are serialized to bytes, then a keyed Fisher-Yates **bit permutation** (seeded via
   BLAKE2b of `K_pbox`) is applied and the byte stream is reversed.
3. Backward-direction pass over the resulting nibbles using `S0_bwd`.

### 4. Wire format
Everything is serialized as zero-padded 3-digit decimal blocks (`000`-`999`):

```
| nonce: 16 bytes (48 chars) | state stream: 24 * L chars | HMAC-SHA256: 32 bytes (96 chars) |
```

The MAC covers `nonce || state stream` and is verified before any decryption work.
Any altered digit raises `VornError`.

## Limitations

- No formal security analysis; the construction is non-standard.
- Python offers no real constant-time guarantees.
- Not suitable for large files.

## Tests

```bash
pip install pytest
python -m pytest
```

## License

MIT
