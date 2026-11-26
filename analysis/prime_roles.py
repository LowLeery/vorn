"""Can primes play a role in Vorn-P that measurably helps? Two candidate roles, tested fairly.

Usage:  python analysis/prime_roles.py        (needs numpy, several minutes)

DECISION RULE (fixed before running, to avoid tuning the question until it says yes):
A prime-based rule counts as useful only if it beats the matching NON-prime controls by more
than two standard deviations of those controls' spread, on the diffusion score below.
Otherwise it is a design signature, not a security feature.

Diffusion score = fraction of (input bit, output bit) cells whose differential bias is flagged
(|z| > 6) after r rounds. Lower is better; a random permutation scores about 0. It measures
how fast the permutation spreads differences. It is NOT a security proof: faster diffusion
does not bound differential or linear trails.

Experiment A  rotation constants. Quarter-round rotations (16, 12, 8, 7) in ChaCha. Compare
              400 random rotation sets drawn from the primes {2,3,5,7,11,13,17,19,23,29,31}
              with 400 drawn from all values 1..31.
Experiment B  word shuffle between rounds. Instead of alternating columns/diagonals, apply
              the column step every round followed by a word permutation. Compare
              prime-stride shuffles (i -> i * (p mod 16) mod 16 using the odd primes in order)
              with random odd strides and random permutations, and with the ChaCha topology.
"""

import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
from vorn import core  # noqa: E402

RNG = np.random.default_rng(20261126)
COLUMNS = ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15))
DIAGONALS = ((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14))
CHACHA_ROTS = (16, 12, 8, 7)
PRIME_SET = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31)
FLAG = 6.0


def rotl(x, n):
    return (x << np.uint32(n)) | (x >> np.uint32(32 - n))


def vperm(state, rounds, rots=CHACHA_ROTS, shuffles=None):
    """Vorn-P variant. shuffles=None: ChaCha topology (columns, diagonals alternating).
    Otherwise columns every round, then word permutation shuffles[r] (list of 16 indices)."""
    r1, r2, r3, r4 = rots
    s = [state[:, i].copy() for i in range(16)]
    for r in range(rounds):
        s[core._LANE[r]] ^= np.uint32(core._RC[r])
        quads = (DIAGONALS if r & 1 else COLUMNS) if shuffles is None else COLUMNS
        for a, b, c, d in quads:
            s[a] = s[a] + s[b]
            s[d] = rotl(s[d] ^ s[a], r1)
            s[c] = s[c] + s[d]
            s[b] = rotl(s[b] ^ s[c], r2)
            s[a] = s[a] + s[b]
            s[d] = rotl(s[d] ^ s[a], r3)
            s[c] = s[c] + s[d]
            s[b] = rotl(s[b] ^ s[c], r4)
        if shuffles is not None:
            s = [s[j] for j in shuffles[r]]
    return np.stack(s, axis=1)


def bits(x):
    return np.unpackbits(np.ascontiguousarray(x).view(np.uint8), axis=1, bitorder="little")


def flip(state, k):
    out = state.copy()
    out[:, k // 32] ^= np.uint32(1 << (k % 32))
    return out


class Probe:
    """Common random numbers: every variant sees the same states and the same input bits."""

    def __init__(self, n, n_inputs):
        self.n = n
        self.base = RNG.integers(0, 2**32, size=(n, 16), dtype=np.uint32)
        self.inputs = sorted(RNG.choice(512, size=n_inputs, replace=False).tolist())

    def score(self, rounds, **cfg):
        """Fraction of probed cells with |z| > FLAG after `rounds` rounds."""
        out0 = vperm(self.base, rounds, **cfg)
        sigma = 0.5 / np.sqrt(self.n)
        flagged = 0
        for k in self.inputs:
            d = bits(out0 ^ vperm(flip(self.base, k), rounds, **cfg)).mean(axis=0)
            flagged += int((np.abs(d - 0.5) / sigma > FLAG).sum())
        return flagged / (len(self.inputs) * 512)


def full_profile(label, rounds_list=(1, 2, 3, 4, 5, 6), **cfg):
    probe = Probe(8192, 512)
    scores = [probe.score(r, **cfg) for r in rounds_list]
    first_clean = next((r for r, v in zip(rounds_list, scores) if all(x == 0 for x in scores[rounds_list.index(r):])), None)
    cells = "  ".join(f"r{r}:{v * 100:6.2f}%" for r, v in zip(rounds_list, scores))
    print(f"  {label:38s} {cells}   clean from round: {first_clean}")


def summarize(name, values):
    v = np.array(values) * 100
    print(f"  {name:28s} n={len(v):3d}  mean {v.mean():6.2f}%  sd {v.std():5.2f}  best {v.min():6.2f}%  median {np.median(v):6.2f}%  worst {v.max():6.2f}%")
    return v


def experiment_a(samples=400):
    print("=" * 100)
    print("EXPERIMENT A: choice of rotation constants (score = % flagged cells, lower is better)")
    probe = Probe(2048, 96)
    for rounds in (2, 3):
        t0 = time.time()
        chacha = probe.score(rounds)
        prime_sets = [tuple(RNG.choice(PRIME_SET, size=4, replace=False)) for _ in range(samples)]
        any_sets = [tuple(RNG.choice(np.arange(1, 32), size=4, replace=False)) for _ in range(samples)]
        pr = [probe.score(rounds, rots=tuple(int(x) for x in s)) for s in prime_sets]
        an = [probe.score(rounds, rots=tuple(int(x) for x in s)) for s in any_sets]
        print(f"\nafter {rounds} rounds ({time.time() - t0:.0f}s): ChaCha (16,12,8,7) scores {chacha * 100:.2f}%")
        vp = summarize("rotations from primes", pr)
        va = summarize("rotations from 1..31", an)
        gap = (va.mean() - vp.mean()) / max(va.std(), 1e-9)
        print(f"  prime-set mean minus any-set mean = {vp.mean() - va.mean():+.2f} points ({-gap:+.2f} sd of the 1..31 spread)")
        best_p = prime_sets[int(np.argmin(pr))]
        best_a = any_sets[int(np.argmin(an))]
        print(f"  best prime set {tuple(int(x) for x in best_p)}, best 1..31 set {tuple(int(x) for x in best_a)}")
        if rounds == 3:
            global BEST_A_P, BEST_A_ANY
            BEST_A_P, BEST_A_ANY = tuple(int(x) for x in best_p), tuple(int(x) for x in best_a)
    print("\nFull-strength profile (all 512 input bits, 8192 pairs) of the finalists:")
    full_profile("ChaCha rotations (16,12,8,7)")
    full_profile(f"best prime set {BEST_A_P}", rots=BEST_A_P)
    full_profile(f"best 1..31 set {BEST_A_ANY}", rots=BEST_A_ANY)


def stride_perm(stride):
    return [(i * stride) % 16 for i in range(16)]


def experiment_b(samples=40):
    print("\n" + "=" * 100)
    print("EXPERIMENT B: word shuffle between rounds (columns every round + shuffle)")
    probe = Probe(2048, 96)
    odd_primes = [p for p in core._PRIMES if p % 2 == 1]
    prime_shuffles = [stride_perm(odd_primes[r % len(odd_primes)] % 16) for r in range(20)]
    for sh in prime_shuffles[:3]:
        assert sorted(sh) == list(range(16))
    print("prime strides used:", [p % 16 for p in odd_primes[:12]], "...")
    odd = [1, 3, 5, 7, 9, 11, 13, 15]
    for rounds in (2, 3, 4):
        base = probe.score(rounds)
        cols_only = probe.score(rounds, shuffles=[list(range(16))] * 20)
        pr = probe.score(rounds, shuffles=prime_shuffles)
        rand_odd = [probe.score(rounds, shuffles=[stride_perm(int(RNG.choice(odd))) for _ in range(20)]) for _ in range(samples)]
        rand_perm = [probe.score(rounds, shuffles=[RNG.permutation(16).tolist() for _ in range(20)]) for _ in range(samples)]
        print(f"\nafter {rounds} rounds:")
        print(f"  ChaCha topology (alternating)          {base * 100:6.2f}%")
        print(f"  columns only, no shuffle (control)     {cols_only * 100:6.2f}%")
        print(f"  prime-stride shuffle                   {pr * 100:6.2f}%")
        vo = summarize("random odd strides", rand_odd)
        vr = summarize("random permutations", rand_perm)
        print(f"  prime-stride minus random-odd mean = {pr * 100 - vo.mean():+.2f} points ({(pr * 100 - vo.mean()) / max(vo.std(), 1e-9):+.2f} sd of controls)")
    print("\nFull-strength profile of the finalists:")
    full_profile("ChaCha topology")
    full_profile("prime-stride shuffle", shuffles=prime_shuffles)


def main():
    t = time.time()
    experiment_a()
    experiment_b()
    print(f"\ntotal {time.time() - t:.0f}s")


if __name__ == "__main__":
    main()
