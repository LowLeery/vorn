# Vorn-2: an experimental duplex-sponge AEAD with prime-hopping round constants

*Draft for IACR ePrint. Author: LowLeery. Version 0.2.4. Status: unreviewed.*

## Abstract

We describe Vorn-2, an authenticated cipher built as a duplex sponge (rate 256 bits, capacity
256 bits) over a 512-bit, 20-round ARX permutation, Vorn-P. The permutation uses the ChaCha
quarter-round; its round constants are the fractional parts of square roots of the first 20 primes
and are injected into the state lane given by the prime modulo 16 ("prime hopping"). We give the
specification, three interoperable implementations (Python, JavaScript, Rust) with shared
test vectors, and the results of our own analysis: full diffusion after 3 rounds, statistical
tests on keystream, reduced-round distinguishers up to 3 rounds, a heuristic differential
trail search, and three ablation experiments that show **prime hopping adds no measurable
security** compared with other constant placements. We also report how an earlier design
(Vorn 0.1.0) was broken in 0.2 s without the key. Vorn-2 has had no third-party review and
should not be used to protect real data. We publish it to invite cryptanalysis.

## 1. Introduction

Vorn started as an experiment in using prime numbers as the source of structure in a cipher.
The first version (0.1.0) derived its keystream from a recurrence over primes with small secret
parameters and was broken by a short script that never touched the password (section 7). Vorn-2
replaces it with a conventional, analysable construction and keeps the prime idea only where it
cannot hurt: the round constants.

Contributions: (1) a fully specified AEAD with test vectors; (2) interoperable implementations;
(3) an honest negative result on the value of the prime-based constants; (4) a list of what is
not yet analysed.

## 2. Specification (summary; SPEC.md is normative)

State: 16 little-endian 32-bit words. Initial state: `LABEL(16 B) || nonce(16 B) || key(32 B)`;
rate = words 0-7, capacity = words 8-15.

Vorn-P round r (0-based): XOR the constant `RC[r] = floor(2^32 * frac(sqrt(p_r)))` (p_r the
(r+1)-th prime) into lane `p_r mod 16`; then apply the ChaCha quarter-round
(rotations 16, 12, 8, 7) to the four columns (r even) or the four diagonals (r odd). 20 rounds,
no feed-forward.

Mode: absorb associated data in 32-byte blocks with pad10*, apply the domain separator
(`state[63] ^= 1`), encrypt by XORing plaintext into the rate (duplex), XOR the key into the
capacity before the final permutation, and output the tag `state[48:64] xor key[16:32]`.
Password mode derives the 256-bit key with scrypt (default n = 2^16, r = 8, p = 1) and stores
`"VRN2" | log_n | r | p | salt | nonce | ciphertext | tag`, authenticating the header.

## 3. Design rationale

*Sponge/duplex:* standard, with known generic bounds that depend on the permutation behaving
like a random one. *ChaCha quarter-round:* well studied; we add no new non-linear component.
*No feed-forward:* the permutation must be invertible for the sponge framing. *Constants:* square
roots of primes are "nothing up my sleeve" numbers as in SHA-256; they break the symmetry of
the round function. *Prime hopping:* the lane of injection follows the prime, so constants do
not all land in the same word; this is the signature of the design.

## 4. Implementations and testing

Python (pure, with an independent second implementation for cross-checking), JavaScript, Rust
(zero dependencies, own scrypt and SHA-256). All agree on known-answer vectors for the
permutation, the AEAD and the password container; containers of the three implementations
decrypt each other's output at default scrypt cost.

## 5. Analysis

*Diffusion:* every output bit flips with probability about 1/2 after 3 rounds.
*Statistics:* 20/20 SP 800-22-style tests pass on keystream (this is weak evidence).
*Reduced rounds:* differential, integral and nonce-difference distinguishers exist up to 3 rounds
and none from 4, a 5x margin against these simple tests.
*Differential trails (beam search, Lipmaa-Moriai weights):* best trails found have probability
2^-6 (1 round), 2^-63 (2), 2^-200 (3), 2^-368 (4); these are upper bounds on the minimum weight
(a lighter trail may exist).
*Algebraic degree (random cubes):* random-looking from 3 rounds.
*Key leakage:* no first or second order bias between key bits and keystream at 1-8 and 20 rounds
(positive control passes).
*Linear analysis:* our linear tests are inconclusive: they do not detect even one round.

## 6. Do primes add security?

Three experiments with a pre-registered decision rule: (a) ablation of the placement rule
against fixed, sequential and random lanes; (b) primes as rotation constants; (c) a
prime-stride word shuffle. None showed a measurable benefit, and (c) is structurally broken
because `i * s mod 16` preserves `i mod 4`. We therefore claim no security from prime hopping;
any strength comes from the sponge mode and the ARX permutation.

## 7. A broken predecessor

Vorn 0.1.0 chained each step on the previous ciphertext value and drew its secret parameters
from sets of about 360,000 combinations in total; a script recovered them uniquely from the
ciphertext in 0.2 s. Lesson: the secret space was small and the structure leaked it.

## 8. Limitations and open problems

No proven bound on differential or linear trails (needs MILP/SAT), no linear analysis, no
optimised integral or algebraic attack, no real key-recovery attempt on reduced rounds, no review
of the duplex framing, implementations not constant-time, scrypt code not audited.

## 9. Availability

Source, specification, vectors and all experiment scripts: https://github.com/LowLeery/vorn
(MIT). Packages: `vorn` on PyPI and crates.io, `@leery10/vorn` on npm.

## References (to complete before submission)

D. J. Bernstein, ChaCha, a variant of Salsa20 (2008). G. Bertoni, J. Daemen, M. Peeters,
G. Van Assche, Duplexing the sponge (2011) and Cryptographic sponge functions. H. Lipmaa,
S. Moriai, Efficient algorithms for computing differential properties of addition (FSE 2001).
J. Wallén, Linear approximations of addition modulo 2^n (FSE 2003). C. Percival, Stronger key
derivation via sequential memory-hard functions (scrypt, 2009; RFC 7914). NIST SP 800-22.
