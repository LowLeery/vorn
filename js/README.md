# vorn (JavaScript / Node.js)

> **Experimental research cipher. Not reviewed by third parties. Do not use it to protect real
> secrets.** For real use, rely on Node's built-in `crypto` (AES-256-GCM or ChaCha20-Poly1305).

**Vorn-2** is an authenticated cipher (AEAD): a duplex sponge over a 512-bit ARX permutation
with prime-hopping round constants. This package has no dependencies, ships TypeScript types and
needs **Node 18+** (it uses `node:crypto` for scrypt and randomness). Python and Rust
implementations produce identical results.

- Project, status, roadmap: <https://github.com/LowLeery/vorn>
- Specification and test vectors: <https://github.com/LowLeery/vorn/blob/main/SPEC.md>
- Analysis so far and what is still missing: <https://github.com/LowLeery/vorn/blob/main/ANALYSIS.md>
- **Cryptanalysis is invited**: please open an issue with anything you find.

## Install

```bash
npm install @leery10/vorn
```

## Password mode

```js
import { encrypt, decrypt, VornError } from '@leery10/vorn';

const blob = encrypt('hello', 'correct-horse-battery-staple');                 // Uint8Array
const text = encrypt('hello', 'correct-horse-battery-staple', { armor: true }); // base64url string

try {
  console.log(Buffer.from(decrypt(blob, 'correct-horse-battery-staple')).toString()); // hello
  decrypt(text, 'correct-horse-battery-staple');
} catch (e) {
  if (e instanceof VornError) console.log('wrong password or modified data');
  else throw e;
}
```

Options for `encrypt`: `aad` (authenticated, unencrypted extra data), `logN` (default 16),
`r` (8), `p` (1), `armor`. `decrypt` accepts `{ aad }`. Both are synchronous; scrypt with the
defaults takes about a quarter of a second.

Containers are byte-for-byte compatible with the Python package, so data encrypted in one can
be decrypted in the other.

## Raw AEAD

```js
import { randomBytes } from 'node:crypto';
import { seal, unseal } from '@leery10/vorn';

const key = new Uint8Array(randomBytes(32));
const nonce = new Uint8Array(randomBytes(16)); // never reuse a (key, nonce) pair
const sealed = seal(key, nonce, 'payload', 'header');   // ciphertext || 16-byte tag
unseal(key, nonce, sealed, 'header');                   // throws VornError if anything was changed
```

## Performance and limits

About 40 MB/s on a single core. Not constant-time (JavaScript cannot promise that), no memory
wiping. Node only; there is no browser build yet.

## License

MIT
