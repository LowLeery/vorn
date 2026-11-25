# Vorn

> **Experimental research cipher. Not reviewed by third parties. Do not use it to protect real
> secrets.** For production use a standard AEAD such as AES-GCM or ChaCha20-Poly1305
> (for example through the `cryptography` package).

**Vorn-2** is an authenticated encryption scheme (AEAD): a duplex sponge over a 512-bit ARX
permutation (ChaCha-style quarter-rounds) whose round constants come from the square roots of
primes and "hop" between state lanes according to the prime. Pure Python, no dependencies.

- Specification and test vectors: [SPEC.md](SPEC.md)
- Analysis done so far (and what is *not* done): [ANALYSIS.md](ANALYSIS.md)
- **Cryptanalysis is invited.** Open an issue with anything you find.

## Install

```bash
pip install vorn
```

## Use

```python
from vorn import encrypt, decrypt, VornError

blob = encrypt("hello", "correct-horse-battery-staple")          # bytes
text = encrypt("hello", "correct-horse-battery-staple", armor=True)  # base64url str

try:
    print(decrypt(blob, "correct-horse-battery-staple"))
    print(decrypt(text, "correct-horse-battery-staple"))
except VornError:
    print("wrong password or modified data")
```

Associated data (authenticated, not encrypted): `encrypt(data, password, aad=b"context")`.

Low level, with your own 32-byte key and a never-reused 16-byte nonce:

```python
import os
from vorn import seal, unseal

key, nonce = os.urandom(32), os.urandom(16)
sealed = seal(key, nonce, b"payload", b"header")   # ciphertext || 16-byte tag
unseal(key, nonce, sealed, b"header")
```

## Performance

About 380 kB/s in pure Python (1 MB in 2.6 s). The password API uses scrypt (default
n = 2^16) and takes about a quarter of a second per call. Meant for small payloads.

## Version note

`vorn` 0.1.0 used an unrelated, broken construction and is not compatible with 0.2. Do not use it.

## Tests

```bash
pip install pytest
python -m pytest
```

## License

MIT
