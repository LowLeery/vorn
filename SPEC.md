# Vorn-2 specification (draft 0.2)

Status: **experimental draft**. No third-party review. No security claims are made beyond the
informal reasoning in section 7. Do not use Vorn-2 to protect real secrets.

## 1. Overview

Vorn-2 is an authenticated encryption scheme (AEAD) with associated data. It is a duplex sponge
over a 512-bit permutation, **Vorn-P**, built from ChaCha-style ARX quarter-rounds.
Round constants come from the square roots of the first 20 primes, and the lane that receives
each constant "hops" according to the prime itself (the Vorn-specific part of the design).

| parameter | value |
|---|---|
| state | 512 bits = 16 little-endian 32-bit words (64 bytes) |
| rate / capacity | 256 bits (32 bytes) / 256 bits (32 bytes) |
| key | 256 bits |
| nonce | 128 bits |
| tag | 128 bits |
| rounds of Vorn-P | 20 |

Byte `i` of the state is byte `i mod 4` of word `i div 4` (little-endian). Bytes 0..31 are the
rate, bytes 32..63 the capacity.

## 2. The permutation Vorn-P

### 2.1 Constants

Let `p_0, p_1, ..., p_19` be the first 20 primes (2, 3, 5, ..., 71). For each round `r`:

- `RC_r = floor(2^32 * frac(sqrt(p_r)))`, the first 32 fractional bits of the square root
  (computed exactly as `isqrt(p_r << 64) mod 2^32`). This is the same "nothing up my sleeve"
  construction as the SHA-256 initial words; `RC_0..RC_3` equal the SHA-256 initial hash words
  `6a09e667 bb67ae85 3c6ef372 a54ff53a`, which is a built-in sanity check.
- `lane_r = p_r mod 16`, the index of the state word that receives the constant.

| r | prime | lane | RC_r |
|---|---|---|---|
| 0 | 2 | 2 | `6a09e667` |
| 1 | 3 | 3 | `bb67ae85` |
| 2 | 5 | 5 | `3c6ef372` |
| 3 | 7 | 7 | `a54ff53a` |
| 4 | 11 | 11 | `510e527f` |
| 5 | 13 | 13 | `9b05688c` |
| 6 | 17 | 1 | `1f83d9ab` |
| 7 | 19 | 3 | `5be0cd19` |
| 8 | 23 | 7 | `cbbb9d5d` |
| 9 | 29 | 13 | `629a292a` |
| 10 | 31 | 15 | `9159015a` |
| 11 | 37 | 5 | `152fecd8` |
| 12 | 41 | 9 | `67332667` |
| 13 | 43 | 11 | `8eb44a87` |
| 14 | 47 | 15 | `db0c2e0d` |
| 15 | 53 | 5 | `47b5481d` |
| 16 | 59 | 11 | `ae5f9156` |
| 17 | 61 | 13 | `cf6c85d3` |
| 18 | 67 | 3 | `2f73477d` |
| 19 | 71 | 7 | `6d1826ca` |

### 2.2 Round function

State words `x[0..15]`. For `r = 0 .. 19`:

1. `x[lane_r] ^= RC_r`  (prime-hopping constant injection)
2. if `r` is even apply `QR` to the four columns
   `(0,4,8,12) (1,5,9,13) (2,6,10,14) (3,7,11,15)`;
   if `r` is odd apply `QR` to the four diagonals
   `(0,5,10,15) (1,6,11,12) (2,7,8,13) (3,4,9,14)`.

`QR(a, b, c, d)` is the ChaCha quarter-round on 32-bit words (`+` is addition mod 2^32):

```
a += b; d ^= a; d <<<= 16
c += d; b ^= c; b <<<= 12
a += b; d ^= a; d <<<=  8
c += d; b ^= c; b <<<=  7
```

There is no feed-forward addition: Vorn-P is a bijection.

## 3. The AEAD mode

Inputs: key `K` (32 bytes), nonce `N` (16 bytes), associated data `A`, plaintext `P`.
Output: ciphertext `C` (same length as `P`) and tag `T` (16 bytes). Sealed form is `C || T`.

```
S = "Vorn-2 AEAD v0.2" || N || K        // 16 + 16 + 32 bytes; label and nonce in the rate, key in the capacity
S = Vorn-P(S)

// associated data: full blocks, then one padded block (always present, pad10* with byte 0x80)
for each full 32-byte block B of A:  S[0:32] ^= B;  S = Vorn-P(S)
L = remaining bytes of A (possibly empty) || 0x80
S[0:len(L)] ^= L;  S = Vorn-P(S)

S[63] ^= 0x01                           // domain separation

// message: the rate is overwritten with ciphertext
for each full 32-byte block B of P:
    X = B ^ S[0:32];  S[0:32] = X (encrypt) / B (decrypt);  output X;  S = Vorn-P(S)
R = remaining bytes of P (possibly empty), m = len(R)
X = R ^ S[0:m];  S[0:m] = X (encrypt) / R (decrypt);  output X
S[m] ^= 0x80

// finalisation
S[32:64] ^= K
S = Vorn-P(S)
T = S[48:64] ^ K[16:32]
```

Decryption recomputes `T` and compares in constant time (`hmac.compare_digest`). Plaintext is
released only if the tags match. **A (key, nonce) pair must never be reused**; reuse reveals
the XOR of plaintexts and breaks authenticity.

## 4. Password-based container (reference implementation)

```
offset  size  field
0       4     magic "VRN2"
4       1     log2(n) for scrypt
5       1     r
6       1     p
7       16    salt  (random)
23      16    nonce (random)
39      ...   ciphertext || 16-byte tag
```

`K = scrypt(password_utf8, salt, n = 2^log_n, r, p, dklen = 32)`. Defaults: `log_n = 16`,
`r = 8`, `p = 1`. The AEAD associated data is `header (39 bytes) || user_aad`, so the scrypt
parameters, salt and nonce are authenticated. Decryption refuses parameters outside
`1 <= log_n <= 24`, `1 <= r <= 32`, `1 <= p <= 16`, or needing more than 512 MiB, to avoid
denial of service through crafted headers. An "armored" form is the unpadded base64url encoding
of the whole blob.

## 5. Test vectors

Produced by the fast implementation and cross-checked against an independently structured
reference implementation (`tests/reference.py`, byte-at-a-time, no shared code). All values
are hexadecimal.

Vorn-P applied to the all-zero 64-byte state:

```
835328e0be86d2e9aef129bb6679da0c0b5fe4e5ac9e4397e4f3687d1d3010c1309a6d16afb7a1b5a8fd8d2104b1b9f68ea64881c30abc73875f495bc1ca950f
```

AEAD vector 1:

```
key   = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
nonce = 808182838485868788898a8b8c8d8e8f
aad   = (empty)
pt    = (empty)
out   = 7587db186fc5ccdbb34a71004186f724   (ciphertext || tag)
```

AEAD vector 2:

```
key   = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
nonce = 808182838485868788898a8b8c8d8e8f
aad   = 766f726e
pt    = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f60616263
out   = 695785ea113073002d72901443eb4cdb1f80f19c390ace308e8df759edcbd840677d56d9a1a4d8cc634433421d2f6b74098e71849af3eeaab90f47c64ddec19700d22213924fdd062581566238538139535d45ab52c9cb3462a91b8b61f8fcb55b03dee72117e36df803635216bfc207c58ff478   (ciphertext || tag)
```

AEAD vector 3:

```
key   = 0000000000000000000000000000000000000000000000000000000000000000
nonce = 00000000000000000000000000000000
aad   = 686561646572
pt    = 54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67
out   = ba0b2da78b07eab84df5543e632ca0bc0368f7597118dd367954bf5d708d20416069231d312da7ac96e76ba67e75b2406619b9dd586c2470216ca6   (ciphertext || tag)
```

Password container (section 4), fixed salt `000102...0f`, nonce `101112...1f`, scrypt
`n = 2^10, r = 8, p = 1`, password (UTF-8) `pässwörd-🔑`, user aad `ctx`,
plaintext `Vorn cross-language container test`:

```
blob  = 56524e320a0801000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f30eac20ba907f66495024bc3f3d9813cfd8e23529d48796945200368a2de34b77ed5e8498516ad2637e5a4636a2c809e7998
```

## 6. Design rationale

- **Sponge/duplex mode** gives a single pass, one primitive for encryption and authentication,
  and a well-studied framing (Bertoni, Daemen, Peeters, Van Assche, "Duplexing the sponge",
  2011). The key sits in the capacity at initialisation and is added again before the final
  permutation, the same pattern used by Ascon-AEAD.
- **ARX quarter-round from ChaCha** is a well-studied nonlinear layer that is simple and fast
  in software. The ChaCha core is not designed as a sponge permutation, so the round constants
  (which also break the rotational and slide symmetries of the bare core) are essential.
- **Prime hopping**: constants from the square roots of primes, injected into a lane chosen by
  the prime. This is the identity of Vorn. Its security value is limited to asymmetry between
  rounds; it is not claimed to add strength beyond ordinary round constants. An ablation
  (ANALYSIS.md section 5) found no measurable difference between the prime rule, a fixed lane,
  round robin and random lanes. Primes were also tried for the rotation
  constants and for a word shuffle without benefit (ANALYSIS.md section 5.2).
- **20 rounds** were chosen conservatively relative to measured diffusion: full avalanche is
  reached after 3 rounds (see ANALYSIS.md). Diffusion alone does not bound differential or linear
  attacks, so the margin is a heuristic.

## 7. Security considerations

Informal reasoning only, not a proof and not a claim:

- If Vorn-P behaved like a random permutation and nonces never repeat, generic analyses of
  duplex AEADs with a 256-bit capacity and 128-bit tag suggest roughly 128-bit security. We have
  not re-derived those bounds for this exact framing.
- Vorn-P has not been analysed for differential or linear trails, integral or algebraic
  attacks, rotational or slide distinguishers beyond the checks in ANALYSIS.md.
- With random 128-bit nonces under one key, collisions become likely around 2^64 messages.
- The Python implementation is not constant-time and cannot wipe secrets from memory.
- Nonce reuse is catastrophic for confidentiality and authenticity.
- Version 0.1.0 of the `vorn` package used a different, unrelated and broken construction. It is
  not compatible with Vorn-2 and should not be used.

## 8. Implementations and versioning

| implementation | location | covers |
|---|---|---|
| Python (reference) | `python/vorn/core.py` | permutation, AEAD, password container |
| Python (independent cross-check) | `python/tests/reference.py` | permutation, AEAD (test use only) |
| JavaScript / Node.js | `js/src/index.js` | permutation, AEAD, password container |
| Rust | `rust/src/lib.rs` | permutation, AEAD |

All of them must reproduce every vector in `vectors/vectors.json`. The specification is
versioned with the packages (current: **0.2.1**, wire format unchanged since 0.2.0). Any change
that alters ciphertext or tags requires a new major-minor version and new vectors.
