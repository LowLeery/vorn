# Vorn-2 analysis so far

Everything here was produced by the scripts in `analysis/` and the test suites in `python/`,
`js/` and `rust/`. Run them yourself:

```
pip install numpy pytest
(cd python && python -m pytest)
(cd js && npm test)
(cd rust && cargo test)
python analysis/avalanche.py
python analysis/statistical.py
python analysis/reduced_round.py
python analysis/ablation.py
python analysis/prime_roles.py
```

**What this does not show.** Good diffusion and clean statistics are necessary, not sufficient.
Many weak ciphers pass every test below. There is no differential or linear trail search, no
algebraic analysis, no key-recovery attempt and no third-party review. The linear tests that
were run are **inconclusive** (section 4). Treat Vorn-2 as an unreviewed research design.

## 1. Correctness testing

- Python: 84 tests. Known-answer vectors for the permutation, the AEAD and the password
  container; cross-check against an independent, byte-at-a-time reference implementation for
  every combination of associated-data and message lengths around the block boundaries
  (0, 1, 31, 32, 33, 64, 65, ...); rejection of every single-bit modification of AEAD and
  password blobs; rejection of truncation and extension; associated-data, key and nonce
  binding; unambiguous AD/message boundary; malformed inputs; refusal of abusive scrypt
  parameters; a check that the shared vector files are in sync.
- JavaScript: 19 tests, including all shared vectors (so the JS code reproduces the Python
  output bit for bit) and the same rejection tests.
- Rust: 24 tests, same shared vectors, plus the password container. The hand-written SHA-256,
  HMAC-SHA-256 and scrypt are checked against Python's `hashlib`/`hmac` (including the RFC 7914
  case with p = 16) and Rust reproduces Python's password containers bit for bit.
- Cross-language: password blobs were decrypted across Python, Node and Rust in both directions
  (unicode password, associated data, default scrypt cost, armored form for Python and Node).

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

## 4. Reduced-round experiments (new in 0.2.1)

`analysis/reduced_round.py` runs the permutation with fewer rounds and looks for anything that
separates it from a random permutation. Numbers are z-scores (deviation divided by its standard
deviation); across the many cells tested a random function reaches about 4.5 to 5.9, so only
values clearly above 6 (7 for E2b) are flagged. Full output:

```
Vorn-P reduced-round experiments (z-scores; random permutation: largest |z| about 4.5-5.3)
flag threshold: |z| > 6.0

E1 differential bias: 512 single-bit input differences x 512 output bits, 16384 pairs each
rounds | max |z| all bits | max |z| rate-only (diff and output in the rate)
     1 |           128.00 |     128.00  <-- distinguisher   (3s)
     2 |           128.00 |     128.00  <-- distinguisher   (3s)
     3 |            45.44 |      10.45  <-- distinguisher   (3s)
     4 |             4.66 |       4.34   (3s)
     5 |             4.84 |       4.67   (3s)
     6 |             5.03 |       4.53   (3s)
     8 |             4.47 |       4.47   (3s)
    20 |             5.34 |       4.14   (5s)

E2 linear bias, single-bit masks: 512 x 512 input/output bits, 65536 samples
INCONCLUSIVE: these masks do not detect even 1 round (which is trivially weak), so this
test is blind for ARX and gives NO evidence of linear resistance.
rounds | max |z| all bits | max |z| rate-only
     1 |             4.60 |       4.08
     2 |             4.61 |       4.61
     3 |             4.54 |       4.10
     4 |             4.57 |       4.23
     5 |             4.57 |       4.36
     6 |             4.72 |       4.55
     8 |             4.63 |       4.36
    20 |             4.41 |       4.10

E2b linear bias, weight-2 input masks (all 32640 pairs of rate bits) x 256 rate output bits, 16384 samples
(8.4 million cells: a random function gives a largest |z| of about 5.5-5.9; flag threshold 7)
INCONCLUSIVE as well: weight-2 masks also miss 1 round, because carries spread the linear
structure over more input bits. A real linear analysis needs trail search (future work).
rounds | max |z|
     1 |    5.53   (4s)
     2 |    5.19   (4s)
     3 |    5.94   (4s)
     4 |    5.47   (4s)
     5 |    5.34   (4s)
     6 |    5.41   (4s)
     8 |    5.39   (4s)
    20 |    5.36   (3s)

E3 integral: XOR of all outputs over a 2^14 cube, 48 random bases, 512 output bits
(z over output bits of 'cube sum = 0' frequency; 'always zero' = output bits that were 0 in all 48 bases)
cube: 14 low bits of word 0
rounds | max |z| | output bits always zero
     1 |    6.93 |   427  <-- distinguisher
     2 |    6.93 |    20  <-- distinguisher
     3 |    3.18 |     0
     4 |    4.04 |     0
     5 |    2.89 |     0
     6 |    3.18 |     0
     8 |    3.46 |     0
    20 |    3.18 |     0
cube: 14 bits spread over rate words 0-7
rounds | max |z| | output bits always zero
     1 |    6.93 |   512  <-- distinguisher
     2 |    6.93 |    71  <-- distinguisher
     3 |    2.89 |     0
     4 |    3.18 |     0
     5 |    2.89 |     0
     6 |    2.89 |     0
     8 |    3.46 |     0
    20 |    3.18 |     0

E4 Vorn-2 AEAD, all internal permutations reduced to r rounds:
one-bit nonce difference -> first ciphertext block (32 B) and tag (16 B), 256 keys x 128 nonce bits
rounds | max |z| over 128 x 384 cells
     1 |   16.00  <-- distinguisher
     2 |    4.38
     3 |    4.00
     4 |    4.12
     5 |    4.50
     6 |    4.12
    20 |    4.25
```

**Summary of what is detectable**

| rounds | E1 differential | E3 integral (2^14 cube) | E4 AEAD nonce difference |
|---|---|---|---|
| 1 | yes (max z 128) | yes (up to 512 output bits constant) | yes (z 16) |
| 2 | yes (z 128) | yes (20 to 71 bits constant) | no |
| 3 | yes (z 45; 10 inside the rate) | no | no |
| 4 to 8 and 20 | no | no | no |

Reading:

- With these tests, structure survives only up to **3 rounds** of the 20. The remaining margin
  against *these simple tests* is about 5 to 6 times.
- The margin against real cryptanalysis is unknown. Dedicated attacks on the ChaCha core,
  whose quarter-round Vorn-P uses, reportedly reach about 7 of its 20 rounds (to our knowledge),
  well beyond what simple statistical tests see. Vorn-P differs (sponge setting, key in the
  capacity, different constants and no feed-forward), so those results do not transfer
  directly, but they show how little a clean statistical result proves.
- **E2 and E2b (linear) are inconclusive.** The masks tested (weight 1 and weight 2 on the
  input) do not detect even a single round, which is clearly weak. The tests are blind, so
  they give no evidence about linear resistance. A real linear analysis needs trail search.
- E4 shows that in the full AEAD, 2 reduced rounds are already enough to hide nonce differences
  from this test, because several permutation calls sit between nonce and output.

## 5. Do primes add strength? (ablation and two more roles, new in 0.2.1)

The distinctive idea of Vorn is "prime hopping": round constant `r` (square root of the r-th
prime) is injected into the lane `p_r mod 16`. `analysis/ablation.py` runs the same permutation
(same quarter-rounds, same constants) with five different injection rules and measures the same
differential statistic as section 4, plus two structural checks:

- column-rotation symmetry: the ChaCha-style round commutes with cyclically rotating the four
  columns, which the constants must break;
- fixed point: the all-zero state must not map to itself.

```
Ablation of the constant-injection rule in Vorn-P (same quarter-rounds, same constants)
E1 columns: max |z| / cells above 6 / cells above 4   (random permutation: ~5 / 0 / ~16)

== prime hopping (Vorn)   lanes: [2, 3, 5, 7, 11, 13, 1, 3, 7, 13]...
rounds | E1 max|z|  >6    >4 | column-rotation symmetry holds | zero state is fixed point
     1 |     90.51 255791 256063 |                           0.00 | False
     2 |     90.51 178274 186385 |                           0.00 | False
     3 |     31.91  1880  3560 |                           0.00 | False
     4 |      4.64     0    21 |                           0.00 | False
     5 |      4.64     0    20 |                           0.00 | False
     6 |      4.62     0    12 |                           0.00 | False
    20 |      5.17     0    11 |                           0.00 | False

== fixed lane 0   lanes: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]...
rounds | E1 max|z|  >6    >4 | column-rotation symmetry holds | zero state is fixed point
     1 |     90.51 255811 256081 |                           0.00 | False
     2 |     90.51 178390 186346 |                           0.00 | False
     3 |     32.70  1800  3331 |                           0.00 | False
     4 |      4.86     0    22 |                           0.00 | False
     5 |      4.51     0    11 |                           0.00 | False
     6 |      4.33     0    17 |                           0.00 | False
    20 |      4.80     0    19 |                           0.00 | False

== round robin   lanes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]...
rounds | E1 max|z|  >6    >4 | column-rotation symmetry holds | zero state is fixed point
     1 |     90.51 255788 256060 |                           0.00 | False
     2 |     90.51 178273 186552 |                           0.00 | False
     3 |     32.70  1781  3360 |                           0.00 | False
     4 |      4.38     0    14 |                           0.00 | False
     5 |      4.88     0    14 |                           0.00 | False
     6 |      4.97     0    14 |                           0.00 | False
    20 |      4.82     0    26 |                           0.00 | False

== random lanes   lanes: [1, 14, 3, 0, 7, 7, 3, 5, 9, 7]...
rounds | E1 max|z|  >6    >4 | column-rotation symmetry holds | zero state is fixed point
     1 |     90.51 255769 256064 |                           0.00 | False
     2 |     90.51 179419 187377 |                           0.00 | False
     3 |     32.75  1865  3457 |                           0.00 | False
     4 |      5.52     0    16 |                           0.00 | False
     5 |      4.97     0    16 |                           0.00 | False
     6 |      4.86     0    14 |                           0.00 | False
    20 |      4.57     0    16 |                           0.00 | False

== no constants   lanes: [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]...
rounds | E1 max|z|  >6    >4 | column-rotation symmetry holds | zero state is fixed point
     1 |     90.51 255788 256079 |                           1.00 | True
     2 |     90.51 179320 187424 |                           1.00 | True
     3 |     32.92  1937  3604 |                           1.00 | True
     4 |      4.77     0    10 |                           1.00 | True
     5 |      5.30     0    20 |                           1.00 | True
     6 |      4.42     0    11 |                           1.00 | True
    20 |      4.88     0    21 |                           1.00 | True
```

**Result.** Prime hopping, a fixed lane, round robin and random lanes behave identically in
this test: all are distinguishable up to 3 rounds and indistinguishable from 4 rounds on, with
the same number of marginal cells. The control without constants shows why constants matter
(symmetry holds, the zero state is a fixed point) but also that this alone does not change
diffusion. So:

- Having round constants is necessary. *Where* they go, including the prime rule, makes **no
  measurable difference** in these tests.
- Prime hopping is therefore a design signature, not a demonstrated security feature. Any
  strength of Vorn-2 comes from the sponge mode and the ARX quarter-rounds, not from the primes.
- These tests could miss subtle effects (for example on specific differential trails). Trail
  search would settle it, and is listed under "not done yet".

### 5.2 Primes for the rotation constants and for a word shuffle (new in 0.2.1)

To give primes a *chance* to matter, two further roles were tried in `analysis/prime_roles.py`.
The decision rule was fixed before running: a prime-based rule counts as useful only if it
beats the matching non-prime controls by more than two standard deviations of the controls'
spread. The score is the share of (input bit, output bit) cells with a flagged differential
bias; lower is better. It measures how fast differences spread, not security.

```
====================================================================================================
EXPERIMENT A: choice of rotation constants (score = % flagged cells, lower is better)

after 2 rounds (81s): ChaCha (16,12,8,7) scores 60.53%
  rotations from primes        n=400  mean  64.23%  sd  5.37  best  57.07%  median  62.66%  worst  80.80%
  rotations from 1..31         n=400  mean  63.23%  sd  4.68  best  56.63%  median  61.97%  worst  80.47%
  prime-set mean minus any-set mean = +1.00 points (+0.21 sd of the 1..31 spread)
  best prime set (19, 17, 7, 31), best 1..31 set (15, 23, 19, 16)

after 3 rounds (89s): ChaCha (16,12,8,7) scores 0.16%
  rotations from primes        n=400  mean   2.92%  sd  6.14  best   0.00%  median   0.63%  worst  43.47%
  rotations from 1..31         n=400  mean   2.08%  sd  4.00  best   0.00%  median   0.54%  worst  28.22%
  prime-set mean minus any-set mean = +0.84 points (+0.21 sd of the 1..31 spread)
  best prime set (13, 5, 3, 7), best 1..31 set (17, 22, 4, 30)

Full-strength profile (all 512 input bits, 8192 pairs) of the finalists:
  ChaCha rotations (16,12,8,7)           r1: 97.58%  r2: 68.04%  r3:  0.70%  r4:  0.00%  r5:  0.00%  r6:  0.00%   clean from round: 4
  best prime set (13, 5, 3, 7)           r1: 97.59%  r2: 66.56%  r3:  0.08%  r4:  0.00%  r5:  0.00%  r6:  0.00%   clean from round: 4
  best 1..31 set (17, 22, 4, 30)         r1: 97.59%  r2: 64.67%  r3:  0.08%  r4:  0.00%  r5:  0.00%  r6:  0.00%   clean from round: 4

====================================================================================================
EXPERIMENT B: word shuffle between rounds (columns every round + shuffle)
prime strides used: [3, 5, 7, 11, 13, 1, 3, 7, 13, 15, 5, 9] ...

after 2 rounds:
  ChaCha topology (alternating)           60.26%
  columns only, no shuffle (control)      77.26%
  prime-stride shuffle                    78.69%
  random odd strides           n= 40  mean  78.27%  sd  0.64  best  77.26%  median  78.39%  worst  79.79%
  random permutations          n= 40  mean  64.85%  sd  2.46  best  59.99%  median  64.83%  worst  73.52%
  prime-stride minus random-odd mean = +0.42 points (+0.67 sd of controls)

after 3 rounds:
  ChaCha topology (alternating)            0.12%
  columns only, no shuffle (control)      75.00%
  prime-stride shuffle                    75.00%
  random odd strides           n= 40  mean  75.00%  sd  0.00  best  75.00%  median  75.00%  worst  75.00%
  random permutations          n= 40  mean   2.61%  sd  2.96  best   0.17%  median   1.58%  worst  14.39%
  prime-stride minus random-odd mean = +0.00 points (+0.00 sd of controls)

after 4 rounds:
  ChaCha topology (alternating)            0.00%
  columns only, no shuffle (control)      75.00%
  prime-stride shuffle                    75.00%
  random odd strides           n= 40  mean  75.00%  sd  0.00  best  75.00%  median  75.00%  worst  75.00%
  random permutations          n= 40  mean   0.00%  sd  0.00  best   0.00%  median   0.00%  worst   0.00%
  prime-stride minus random-odd mean = +0.00 points (+0.00 sd of controls)

Full-strength profile of the finalists:
  ChaCha topology                        r1: 97.58%  r2: 68.04%  r3:  0.70%  r4:  0.00%  r5:  0.00%  r6:  0.00%   clean from round: 4
  prime-stride shuffle                   r1: 97.57%  r2: 80.57%  r3: 75.00%  r4: 75.00%  r5: 75.00%  r6: 75.00%   clean from round: None

```

**Experiment A (rotation constants).** 400 random rotation sets drawn from the primes were
compared with 400 drawn from all values 1 to 31. Prime sets are **not better**: slightly worse
on average (+0.21 standard deviations), and the best prime set and the best unrestricted set
perform identically at full strength. ChaCha's own (16, 12, 8, 7) is already as good as
anything found: all are clean from round 4.

**Experiment B (word shuffle).** The natural prime idea, a stride shuffle `i -> i * p mod 16`
between rounds, is **structurally broken**: multiplication preserves `i mod 4`, so the four
columns never mix and 75% of the cells (12 of 16 words) stay unaffected forever. Random word
permutations work about as well as the ChaCha column/diagonal alternation, so the primes add
nothing there either.

**Verdict.** Neither role passes the decision rule. After three tests (constant placement,
rotation choice, shuffle) primes show no measurable benefit in Vorn-P, and one natural
prime-based idea is actively harmful. Prime hopping remains a design signature.

## 6. Performance

Measured on one core of a cloud VM.

| implementation | large-message speed | notes |
|---|---|---|
| Python 3.13 (pure) | about 0.4 MB/s (1 MB in 2.6 s) | fine for small payloads |
| Node 22 | about 40 MB/s (10 MB in 0.26 s) | |
| Rust 1.97, release | about 90 to 120 MB/s (50 MB seal in 0.55 s) | zero dependencies |

Ciphertext expansion is 16 bytes (tag), plus 39 bytes of header in the password container.
Password encryption with the default scrypt cost (n = 2^16) takes about 0.2 s in Python (OpenSSL)
and in Rust (own implementation). For comparison,
Vorn 0.1.0 processed about 6 kB/s with a 24x ciphertext expansion.

## 7. Lessons from Vorn 0.1.0

The first version chained each step on the previous **ciphertext** value (public) and drew its
secret parameters from tiny sets (a, b, c, d and an initial state: about 360,000 combinations
in total). A script that never touches the password recovered those parameters uniquely from
the ciphertext in 0.2 seconds, by keeping only candidates that decode to valid prime indices.
That layer therefore added no secrecy. Vorn-2 was redesigned around a wide secret state, a
standard sponge framing and authenticated, binary output; the 0.1.0 release should be
considered insecure and withdrawn.

## 8. Not done yet (invitation to reviewers)

- A *lower bound* on differential trail weight (MILP / SAT) and on active quarter-rounds;
  section 9.1 only gives what a heuristic search finds. A working linear analysis at all
  (section 4).
- Optimised integral and cube attacks, rotational and slide analysis of Vorn-P (section 9.2
  is a random-cube estimate).
- Real key-recovery attempts on reduced-round Vorn-2 (for example 2 to 6 rounds); section 9.3
  only tests simple biases.
- Review of the duplex framing (padding, domain separation, key injection) and a security
  proof or bound.
- Independent implementations in other languages against `vectors/vectors.json`.
- Trail search to settle whether the prime rule matters at all (section 5).
- Constant-time hardened implementation (including the Rust scrypt).

Findings of any kind, including failed attacks, are welcome as GitHub issues.

## 9. Trail search, algebraic degree and key leakage (new in 0.2.4)

Three more experiments, all reproducible with the scripts in `analysis/` and outputs in
`analysis/results/`. None of them is a proof.

### 9.1 Differential trail search (`analysis/trails.py`)

For XOR differences, only modular addition is non-linear. The script uses the exact
Lipmaa-Moriai weight of an addition (self-checked against brute-force counts for 6-bit words)
and runs a beam search over the quarter-rounds of Vorn-P, starting from 32 one-bit differences
in the rate (the part an attacker controls when absorbing a message): the 2 lightest output
differences are kept per addition and the 60 lightest states per step. Weight w means a
characteristic of probability 2^-w.

| rounds | lightest trail found | median over starts |
|---|---|---|
| 1 | 2^-6 | 2^-8 |
| 2 | 2^-63 | 2^-78 |
| 3 | 2^-200 | 2^-205 |
| 4 | 2^-368 | 2^-387 |

Reading: a beam search finds only *upper* bounds on the true minimum weight (a lighter trail
may exist), so this shows what a simple attacker finds, not a security bound. Within that
limit, the picture is consistent with section 4: a 2-round characteristic exists, and from 3
rounds on the best trail found is already beyond 2^-128, so a single differential
characteristic gives nothing against 20 rounds. Not covered: truncated and impossible
differentials, clustering of many trails, differences with several active bits at the start,
rotational differences, and the *linear* case (there is still no working linear analysis).
A proper lower bound needs a MILP or SAT search, which was not available here.

### 9.2 Algebraic degree estimate (`analysis/degree.py`)

XOR of an output bit over a random k-dimensional input cube is 1 with probability 0.5 for a
random function. For Vorn-P with random cubes (not optimised), 1 round gives about 0 for
k >= 2, 2 rounds give 0.15 to 0.25 up to k = 14, and from 3 rounds on the sums look random
for every k tested (0.49 to 0.51). This agrees with the full diffusion after 3 rounds and
with the integral distinguishers of section 4 existing only up to 3 rounds. Optimised cubes
and higher k could do better; this is an estimate, not a degree bound.

### 9.3 Key leakage into the keystream (`analysis/key_bias.py`)

For 1 to 8 and 20 rounds, 2^16 random key and nonce pairs: correlation of every key bit (and
of 512 XORs of two key bits) with every bit of the first keystream block. Largest |z| in every
row: 4.0 to 4.8, as expected for random data (threshold 6). A positive control (key XORed
straight into the output) gives |z| = 256, so the test machinery works. Like the linear
tests, these first and second order statistics are weak and probably do not see 1-round
leaks that need multi-bit relations; so this shows only that no simple bias exists, and it is
**not** a key-recovery attempt. No actual key-recovery attack on reduced rounds was tried.

