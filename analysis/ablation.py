"""Ablation: does "prime hopping" (which lane gets which round constant) add measurable strength?

Usage:  python analysis/ablation.py        (needs numpy, about 1-2 minutes)

The Vorn-P permutation is run with the same quarter-rounds and the same round constants but
with different rules for WHERE each constant is injected:

  prime hopping   lane_r = p_r mod 16            (the Vorn design)
  fixed lane      lane_r = 0 for every round
  round robin     lane_r = r mod 16
  random lanes    lane_r drawn at random once (seeded)
  no constants    nothing is injected (control: should be clearly broken)

For each variant and round count it measures the same things as reduced_round.py:
  - E1 differential: largest |z| over 512 input bits x 512 output bits, and how many cells exceed 6
  - symmetry: the ChaCha-style round commutes with rotating the 4 columns; constants should break it
  - fixed point: the all-zero state must not map to itself
Random-permutation reference for E1: largest |z| about 4.5-5.3, about 16 cells above 4, ~0 above 6.
"""

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
from vorn import core  # noqa: E402

RNG = np.random.default_rng(20261126)
COLUMNS = ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15))
DIAGONALS = ((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14))
ROUNDS = 20
RC = list(core._RC)
PRIMES = list(core._PRIMES)

SCHEDULES = {
    "prime hopping (Vorn)": [(p % 16, rc) for p, rc in zip(PRIMES, RC)],
    "fixed lane 0": [(0, rc) for rc in RC],
    "round robin": [(r % 16, rc) for r, rc in enumerate(RC)],
    "random lanes": [(int(RNG.integers(0, 16)), rc) for rc in RC],
    "no constants": [(0, 0) for _ in RC],
}


def rotl(x, n):
    return (x << np.uint32(n)) | (x >> np.uint32(32 - n))


def vperm(state, rounds, schedule):
    s = [state[:, i].copy() for i in range(16)]
    for r in range(rounds):
        lane, rc = schedule[r]
        s[lane] ^= np.uint32(rc)
        for a, b, c, d in DIAGONALS if r & 1 else COLUMNS:
            s[a] = s[a] + s[b]
            s[d] = rotl(s[d] ^ s[a], 16)
            s[c] = s[c] + s[d]
            s[b] = rotl(s[b] ^ s[c], 12)
            s[a] = s[a] + s[b]
            s[d] = rotl(s[d] ^ s[a], 8)
            s[c] = s[c] + s[d]
            s[b] = rotl(s[b] ^ s[c], 7)
    return np.stack(s, axis=1)


def bits(x):
    return np.unpackbits(np.ascontiguousarray(x).view(np.uint8), axis=1, bitorder="little")


def rand_states(n):
    return RNG.integers(0, 2**32, size=(n, 16), dtype=np.uint32)


def flip(state, k):
    out = state.copy()
    out[:, k // 32] ^= np.uint32(1 << (k % 32))
    return out


COL_ROTATE = [(i // 4) * 4 + ((i % 4) + 1) % 4 for i in range(16)]  # word i moves to this index


def rotate_columns(state):
    out = np.empty_like(state)
    for i in range(16):
        out[:, COL_ROTATE[i]] = state[:, i]
    return out


def e1(schedule, rounds, n=8192):
    base = rand_states(n)
    out0 = vperm(base, rounds, schedule)
    sigma = 0.5 / np.sqrt(n)
    zmax, over6, over4 = 0.0, 0, 0
    for k in range(512):
        d = bits(out0 ^ vperm(flip(base, k), rounds, schedule)).mean(axis=0)
        z = np.abs(d - 0.5) / sigma
        zmax = max(zmax, float(z.max()))
        over6 += int((z > 6).sum())
        over4 += int((z > 4).sum())
    return zmax, over6, over4


def symmetry(schedule, rounds, n=256):
    base = rand_states(n)
    a = vperm(rotate_columns(base), rounds, schedule)
    b = rotate_columns(vperm(base, rounds, schedule))
    return float((a == b).all(axis=1).mean())


def zero_fixed_point(schedule, rounds):
    z = np.zeros((1, 16), dtype=np.uint32)
    return bool((vperm(z, rounds, schedule) == z).all())


def main():
    print("Ablation of the constant-injection rule in Vorn-P (same quarter-rounds, same constants)")
    print("E1 columns: max |z| / cells above 6 / cells above 4   (random permutation: ~5 / 0 / ~16)\n")
    rounds_list = (1, 2, 3, 4, 5, 6, 20)
    for name, sched in SCHEDULES.items():
        print(f"== {name}   lanes: {[l for l, _ in sched[:10]]}...")
        print("rounds | E1 max|z|  >6    >4 | column-rotation symmetry holds | zero state is fixed point")
        for r in rounds_list:
            zmax, o6, o4 = e1(sched, r)
            print(f"{r:6d} | {zmax:9.2f} {o6:5d} {o4:5d} | {symmetry(sched, r):30.2f} | {zero_fixed_point(sched, r)}")
        print()


if __name__ == "__main__":
    main()
