"""Algebraic degree estimate of Vorn-P output bits (cube-sum test).

Usage:  python analysis/degree.py        (needs numpy, about 1-2 minutes)

If the XOR of an output bit over a k-dimensional cube of inputs is 0 for EVERY cube (and every
setting of the other inputs), the bit has degree < k in the cube variables. For each round
count r we take random cubes of dimension k over input bits (anywhere in the 512-bit state), with
random values for all other bits, and report the smallest k for which some output bit's cube
sum is non-zero often (more than 5 percent of trials). Above that k the output is not
distinguishable from random by this test; below it the cube sum is (almost) always zero, which
is a distinguisher (integral property).

This is an experimental degree *estimate*: the true degree can be higher than the smallest k
that shows non-zero sums, and cubes are random, not optimised. It is not a proof.
"""

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from reduced_round import bits, vperm  # noqa: E402

RNG = np.random.default_rng(20261126)
TRIALS = 24
K_MAX = 14


def cube_nonzero_fraction(rounds: int, k: int) -> float:
    """Fraction of (trial, output bit) cells whose cube sum is non-zero, averaged over trials."""
    fracs = []
    for _ in range(TRIALS):
        base = RNG.integers(0, 1 << 32, size=(1, 16), dtype=np.uint64).astype(np.uint32)
        pos = RNG.choice(512, size=k, replace=False)
        idx = np.arange(1 << k, dtype=np.uint32)
        state = np.repeat(base, 1 << k, axis=0)
        flat = np.unpackbits(state.view(np.uint8), axis=1, bitorder="little").reshape(1 << k, 512)
        for j, p in enumerate(pos):
            flat[:, p] = (idx >> j) & 1
        state = np.packbits(flat, axis=1, bitorder="little").view(np.uint32).reshape(1 << k, 16)
        out = bits(vperm(state, rounds))
        fracs.append(np.bitwise_xor.reduce(out, axis=0).mean())
    return float(np.mean(fracs))


def main():
    shown = (1, 2, 3, 4, 6, 8, 10, 14)
    print("rounds | smallest k with fraction >= 0.45 (random-looking) | fraction of cube sums equal to 1")
    print(f"       |                                                   | at k = {', '.join(map(str, shown))}  (0.5 = random)\n")
    for rounds in (1, 2, 3, 4, 5, 6):
        first, row = None, []
        for k in range(1, K_MAX + 1):
            f = cube_nonzero_fraction(rounds, k)
            if first is None and f >= 0.45:
                first = k
            if k in shown:
                row.append(f"{f:.2f}")
        print(f"  {rounds:>2}   | {('k = ' + str(first)) if first else 'not reached (> 14)':<49} | " + "  ".join(row), flush=True)


if __name__ == "__main__":
    main()
