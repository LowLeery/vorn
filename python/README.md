# vorn (Python)

> **Experimental research cipher. Not reviewed by third parties. Do not use it to protect real
> secrets.** For real use, take AES-GCM or ChaCha20-Poly1305 from the `cryptography` package.

**Vorn-2** is an authenticated cipher (AEAD): a duplex sponge over a 512-bit ARX permutation
with prime-hopping round constants. Pure Python, no dependencies, Python 3.10+.
JavaScript and Rust implementations produce identical results.

- Project, status, roadmap: <https://github.com/LowLeery/vorn>
- Specification and test vectors: <https://github.com/LowLeery/vorn/blob/main/SPEC.md>
- Analysis so far and what is still missing: <https://github.com/LowLeery/vorn/blob/main/ANALYSIS.md>
- **Cryptanalysis is invited**: please open an issue with anything you find.

## Install

```bash
pip install vorn
```

## Password mode

```python
from vorn import encrypt, decrypt, VornError

blob = encrypt("hello", "correct-horse-battery-staple")                 # bytes
text = encrypt("hello", "correct-horse-battery-staple", armor=True)     # base64url str

try:
    print(decrypt(blob, "correct-horse-battery-staple"))   # b'hello'
    print(decrypt(text, "correct-horse-battery-staple"))
except VornError:
    print("wrong password or modified data")
```

- Data may be `str` (UTF-8) or `bytes`.
- `aad=b"context"` adds authenticated, unencrypted associated data.
- The key comes from scrypt (default `log_n=16`, `r=8`, `p=1`, about 0.25 s). Tune with
  `log_n=`, `r=`, `p=`.
- Output layout: `"VRN2" | log2(n) | r | p | salt(16) | nonce(16) | ciphertext | tag(16)`; the
  whole header is authenticated. Decryption refuses scrypt settings above 512 MiB.

## Raw AEAD

```python
import os
from vorn import seal, unseal

key, nonce = os.urandom(32), os.urandom(16)      # never reuse a (key, nonce) pair
sealed = seal(key, nonce, b"payload", b"header")  # ciphertext || 16-byte tag
unseal(key, nonce, sealed, b"header")             # raises VornError if anything was changed
```

## Performance and limits

About 380 kB/s (1 MB in 2.6 s). Meant for small payloads; use the Rust or JavaScript
implementation for speed. Not constant-time, no memory wiping.

## Version note

`vorn` 0.1.0 used an unrelated, broken construction. Do not use it. 0.2.x is a complete
redesign and is not compatible with it.

## License

MIT
