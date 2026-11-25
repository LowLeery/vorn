# Vorn-2 analysis so far

Everything here was produced by the scripts in `analysis/` and the test suite in `tests/`.
Run them yourself:

```
pip install numpy pytest
python -m pytest
python analysis/avalanche.py
python analysis/statistical.py
```

**What this does not show.** Good diffusion and clean statistics are necessary, not sufficient.
Many weak ciphers pass every test below. No differential or linear trail search, no
algebraic or integral analysis, and no third-party review has been done. Treat Vorn-2 as an
unreviewed research design.

## 1. Correctness testing

- 81 automated tests: known-answer vectors, cross-check against an independent reference
  implementation for every combination of associated-data and message lengths around the block
  boundaries (0, 1, 31, 32, 33, 64, 65, ...), rejection of every single-bit modification of
  ciphertext and password-based blobs, rejection of truncation and extension, associated-data,
  key and nonce binding, unambiguous AD/message boundary, malformed inputs, and refusal of
  abusive scrypt parameters.

## 2. Diffusion of the permutation (avalanche)

For random 512-bit states, each input bit is flipped and the output change is measured over
96 samples. Ideal mean Hamming distance is 256. The last two columns look at all 512 x 512
(input bit, output bit) pairs: a random function gives a largest |z| of about 4.9 to 5.3 and
about 16 cells above 4.

```
PART 1: Vorn-P permutation avalanche (512-bit state)
rounds | mean HD (ideal 256) | per-input-bit mean HD min..max | max |z| | cells |z|>4
     1 |               26.62 |   10.52 ..   41.02            |   9.80 | 249993   (0s)
     2 |              182.91 |  134.58 ..  225.35            |   9.80 | 113029   (1s)
     3 |              255.77 |  252.88 ..  258.66            |   5.31 |     27   (1s)
     4 |              256.02 |  252.79 ..  259.45            |   4.90 |     18   (1s)
     5 |              256.05 |  252.69 ..  259.19            |   4.69 |     14   (1s)
     6 |              256.03 |  252.58 ..  259.57            |   4.29 |      8   (1s)
     8 |              256.00 |  252.41 ..  260.10            |   4.49 |      7   (2s)
    10 |              256.02 |  252.08 ..  259.05            |   4.49 |     11   (3s)
    12 |              256.04 |  252.15 ..  259.05            |   4.29 |     16   (3s)
    20 |              255.99 |  252.64 ..  260.00            |   4.29 |     12   (4s)
(random-function reference: max |z| about 4.9-5.3, about 16 cells above 4)
PART 2: Vorn-2 AEAD single-bit avalanche (fraction of output bits that change, ideal 0.5)
key bit -> tag                                                 mean 0.5001  min 0.367  max 0.633
nonce bit -> tag                                               mean 0.4999  min 0.375  max 0.672
aad bit -> tag                                                 mean 0.5007  min 0.367  max 0.625
plaintext bit (block 0) -> ciphertext block 1                  mean 0.4988  min 0.402  max 0.598
plaintext bit (block 0) -> tag                                 mean 0.5000  min 0.359  max 0.641
plaintext bit (block 0) -> ciphertext block 0 (expect 1 bit)   mean 0.0039  min 0.004  max 0.004
```

Reading: after 1 round diffusion is weak, after 2 it is partial, and from **3 rounds** on it
is statistically indistinguishable from a random function in this test. The 20 rounds used by
Vorn-2 are about 6.7 times the round count at which this particular measure saturates. This is
a diffusion margin only. It does not bound differential or linear probabilities.

## 3. Statistical tests on output streams

Five tests (monobit, block frequency, runs, cumulative sums, byte chi-square) on four streams.
This is an in-house implementation in the style of NIST SP 800-22, validated against SciPy for
the special functions and checked to fail on a deliberately biased stream. It is not the
official NIST STS suite.

```
ciphertext of 512 KiB zero message (single key/nonce)  (524288 bytes, 4194304 bits)
  monobit          p = 0.7868  PASS
  block-frequency  p = 0.5957  PASS
  runs             p = 0.3875  PASS
  cumulative-sums  p = 0.5100  PASS
  byte-chi-square  p = 0.5867  PASS

ciphertext, 8192 messages with counter nonces  (524288 bytes, 4194304 bits)
  monobit          p = 0.1377  PASS
  block-frequency  p = 0.2204  PASS
  runs             p = 0.9970  PASS
  cumulative-sums  p = 0.2306  PASS
  byte-chi-square  p = 0.3700  PASS

ciphertext, 8192 messages with counter keys  (524288 bytes, 4194304 bits)
  monobit          p = 0.6274  PASS
  block-frequency  p = 0.9201  PASS
  runs             p = 0.8696  PASS
  cumulative-sums  p = 0.7353  PASS
  byte-chi-square  p = 0.5529  PASS

tags of 16384 empty messages with counter nonces  (262144 bytes, 2097152 bits)
  monobit          p = 0.0257  PASS
  block-frequency  p = 0.9426  PASS
  runs             p = 0.4604  PASS
  cumulative-sums  p = 0.0130  PASS
  byte-chi-square  p = 0.2775  PASS

20/20 tests passed at alpha = 0.01
(with alpha = 0.01 about 1 in 100 tests fails by chance even for ideal random data)
```

## 4. Performance (pure Python 3.13, one core of a cloud VM)

| operation | result |
|---|---|
| seal / unseal 1 kB | 3 ms |
| seal / unseal 100 kB | 0.32 s |
| seal / unseal 1 MB | 2.6 s (about 380 kB/s) |
| ciphertext expansion | 16 bytes (tag), plus 39 bytes header in the password format |
| password encrypt, default scrypt (n = 2^16) | about 0.24 s |

Vorn 0.1.0 processed about 6 kB/s with a 24x ciphertext expansion, so 0.2 is roughly 60 times
faster and almost expansion-free.

## 5. Lessons from Vorn 0.1.0

The first version chained each step on the previous **ciphertext** value (public) and drew its
secret parameters from tiny sets (a, b, c, d and an initial state: about 360,000 combinations
in total). A script that never touches the password recovered those parameters uniquely from
the ciphertext in 0.2 seconds, by keeping only candidates that decode to valid prime indices.
That layer therefore added no secrecy. Vorn-2 was redesigned around a wide secret state, a
standard sponge framing and authenticated, binary output; the 0.1.0 release should be
considered insecure and withdrawn.

## 6. Not done yet (invitation to reviewers)

- Search for differential and linear trails (MILP / SAT) and bounds on active quarter-rounds.
- Integral, cube, algebraic-degree and rotational/slide analysis of Vorn-P.
- Key-recovery attempts on reduced-round Vorn-2 (for example 4 to 8 rounds).
- Review of the duplex framing (padding, domain separation, key injection).
- Independent implementations in other languages against the test vectors in SPEC.md.

Findings of any kind are welcome as GitHub issues.
