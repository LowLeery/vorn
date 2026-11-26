# Vorn

[![CI](https://github.com/LowLeery/vorn/actions/workflows/ci.yml/badge.svg)](https://github.com/LowLeery/vorn/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/vorn)](https://pypi.org/project/vorn/)
[![npm](https://img.shields.io/npm/v/vorn)](https://www.npmjs.com/package/vorn)
[![crates.io](https://img.shields.io/crates/v/vorn)](https://crates.io/crates/vorn)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Vorn-2** is an experimental authenticated cipher (AEAD): a duplex sponge over a 512-bit ARX
permutation whose round constants come from the square roots of primes and *hop* between state
lanes according to the prime. One specification, three implementations (Python, JavaScript,
Rust) that agree bit for bit.

> **Experimental research design. No third-party review. Do not use it to protect real secrets.**
> For anything that matters, use AES-GCM or ChaCha20-Poly1305 from a vetted library. Vorn exists
> to be studied, attacked and improved. See [Security status](#security-status).

## Quick start

**Python**: `pip install vorn`

```python
from vorn import encrypt, decrypt

blob = encrypt("hello", "correct-horse-battery-staple")
print(decrypt(blob, "correct-horse-battery-staple"))   # b'hello'
```

**JavaScript** (Node 18+): `npm install vorn`

```js
import { encrypt, decrypt } from 'vorn';

const blob = encrypt('hello', 'correct-horse-battery-staple');
console.log(Buffer.from(decrypt(blob, 'correct-horse-battery-staple')).toString()); // hello
```

**Rust**: `cargo add vorn` (zero dependencies)

```rust
use vorn::password::{decrypt, encrypt, Params};

let blob = encrypt(b"hello", b"correct-horse-battery-staple", b"", Params::default())?;
let text = decrypt(&blob, b"correct-horse-battery-staple", b"")?;   // b"hello"
```

## How it works

```
 key (256 bit) ─┐                       ┌─ rate 256 bit ── absorbs aad, xors message → ciphertext
 nonce (128 bit)┼─► state 512 bit ─►  Vorn-P  ─►  ...  ─►  tag (128 bit)
 label ─────────┘                       └─ capacity 256 bit (holds the key, never output)
```

- **Mode:** duplex sponge, one pass, key in the capacity at start and again before the tag.
- **Permutation Vorn-P:** 20 rounds of ChaCha-style quarter-rounds, alternating columns and
  diagonals, no feed-forward.
- **Prime hopping (the Vorn part):** round `r` adds the constant `floor(2^32 * frac(sqrt(p_r)))`
  into lane `p_r mod 16`, where `p_r` is the r-th prime. Constants are the same kind of
  "nothing up my sleeve" numbers SHA-256 uses.
  *Honest note:* an ablation found no measurable security difference between this rule and
  other placements. The constants themselves matter (they break symmetry); where they go does
  not, in the tests so far. Prime hopping is the signature of the design, not its strength.
- **Password mode:** scrypt (default n = 2^16) derives the key; salt, nonce and scrypt parameters
  live in an authenticated header.

Full details, constants table and test vectors: **[SPEC.md](SPEC.md)**.

## Implementations

| | package | API | speed* | tests |
|---|---|---|---|---|
| Python | [`vorn`](https://pypi.org/project/vorn/) | password + raw AEAD | ~0.4 MB/s | 84 |
| JavaScript | [`vorn`](https://www.npmjs.com/package/vorn) | password + raw AEAD, TypeScript types | ~40 MB/s | 19 |
| Rust | [`vorn`](https://crates.io/crates/vorn) | password + raw AEAD, zero dependencies | ~100 MB/s | 24 |

\*single core of a cloud VM, large messages. Python is pure Python and meant for small payloads.

All three pass the same known-answer vectors ([vectors/vectors.json](vectors/vectors.json)),
and the password containers of all three decrypt each other's output.

## Security status

What has been done ([ANALYSIS.md](ANALYSIS.md) has the data and the scripts to reproduce it):

- Independent second implementation (`python/tests/reference.py`) cross-checked against the fast
  one on every length around the block boundaries.
- Avalanche: full diffusion of the permutation after 3 of 20 rounds.
- Statistical tests in the style of NIST SP 800-22 on cipher output: 20 of 20 pass.
- Reduced-round experiments: differential and integral distinguishers exist up to 3 rounds and
  vanish from round 4 on, a 5x margin *against these simple tests*.
- Ablation: the prime rule is indistinguishable from fixed, sequential or random placement.
  Two more attempts to give primes a useful role (rotation constants, word shuffle) also showed
  no benefit; the prime-stride shuffle turned out to be structurally broken.

What has **not** been done, and matters far more:

- No differential/linear trail search, no algebraic or integral analysis beyond the above, no
  key-recovery attempts on reduced rounds, no third-party review.
- The linear tests included are **inconclusive** (they do not detect even 1 round).
- The implementations are not hardened against side channels and do not wipe memory.

Passing statistical tests is not evidence of security; many broken ciphers pass them.
An earlier design (Vorn 0.1.0) was broken by a short script that recovered its secret parameters
without the password. That story and its lessons are in [ANALYSIS.md](ANALYSIS.md).

## Cryptanalysis is invited

If you can distinguish, forge, or recover anything, even on reduced rounds, please open an issue.
See [SECURITY.md](SECURITY.md) and [CONTRIBUTING.md](CONTRIBUTING.md). Independent
implementations in other languages are very welcome and can be checked against
[vectors/vectors.json](vectors/vectors.json).

## Roadmap

- [ ] Differential and linear trail search (MILP/SAT) and a real bound on active quarter-rounds
- [ ] Reduced-round key-recovery attempts, algebraic-degree and integral analysis
- [ ] Write-up for IACR ePrint, then outside review
- [ ] WebAssembly/browser build, Go port
- [ ] Constant-time hardened implementation

## Repository layout

```
SPEC.md  ANALYSIS.md        specification, analysis report
python/  js/  rust/         the three implementations (each with its own README and tests)
vectors/                    shared known-answer test vectors (single source of truth: python/tests/vectors.py)
analysis/                   avalanche, statistical and reduced-round experiments (reproducible)
tools/sync_vectors.py       regenerates the JSON and Rust copies of the vectors
```

## License

MIT. If you use Vorn in research, see [CITATION.cff](CITATION.cff).
