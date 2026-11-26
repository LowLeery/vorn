"""Reduced-round key-leakage experiment on Vorn-2.

Usage:  python analysis/key_bias.py        (needs numpy, about 1 minute)

In Vorn-2 the first keystream block is the rate part (words 0-7) of the state after the
permutation, where the initial state is LABEL || nonce || key (key in words 8-15). An attacker
who knows the plaintext sees that block. This script asks, for r = 1..8 and 20 rounds, whether
single key bits leave a detectable trace in single keystream bits:

  K1  first-order bias    correlation of every (key bit, keystream bit) pair over random
                          keys and nonces, as z-scores
  K2  pairwise XOR bias   for 512 random pairs of key bits, correlation of key_i ^ key_j with
                          each keystream bit (second-order leakage)

For a random function the largest |z| over the 256 x 256 cells is about 4.5 to 5; only values
above 6 are flagged. This is a distinguisher test, NOT a key-recovery attack: a flagged cell
would show where a real attack could start; an unflagged table shows only that these simple
statistics find nothing. Like the linear tests in reduced_round.py these first/second-order
statistics are weak: ARX mixes key bits into the output within one round, so they may not see
leaks that need higher-order or multi-bit relations. The positive control only proves that the
machinery detects a gross leak.
"""

import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent))
from reduced_round import bits, vperm  # noqa: E402
from vorn import core  # noqa: E402

RNG = np.random.default_rng(20261126)
N = 1 << 16
FLAG = 6.0


def keystream(rounds, n=N):
    label = np.frombuffer(core.LABEL, dtype="<u4")
    nonce = RNG.integers(0, 1 << 32, size=(n, 4), dtype=np.uint64).astype(np.uint32)
    key = RNG.integers(0, 1 << 32, size=(n, 8), dtype=np.uint64).astype(np.uint32)
    state = np.concatenate([np.tile(label, (n, 1)), nonce, key], axis=1)
    out = vperm(state, rounds)[:, :8]  # rate words = keystream block (plaintext xor handled by attacker)
    return bits(key), bits(np.ascontiguousarray(out))


def control(n=N):
    """Positive control: a deliberately leaky 'cipher' whose keystream is a 0-round permutation
    output with key words XORed into the rate. The test MUST flag it, or the test is blind."""
    label = np.frombuffer(core.LABEL, dtype="<u4")
    nonce = RNG.integers(0, 1 << 32, size=(n, 4), dtype=np.uint64).astype(np.uint32)
    key = RNG.integers(0, 1 << 32, size=(n, 8), dtype=np.uint64).astype(np.uint32)
    out = np.concatenate([np.tile(label, (n, 1)), nonce], axis=1) ^ key
    return bits(key), bits(np.ascontiguousarray(out))


def zmax(kb, ob):
    """Largest |z| of the correlation between columns of kb and ob (both 0/1)."""
    a = kb.astype(np.float32) * 2 - 1
    b = ob.astype(np.float32) * 2 - 1
    c = (a.T @ b) / a.shape[0]
    z = np.abs(c) * np.sqrt(a.shape[0])
    i, j = np.unravel_index(np.argmax(z), z.shape)
    return float(z.max()), int(i), int(j)


def main():
    print(f"N = {N} random (key, nonce) pairs per row; flag threshold |z| > {FLAG}\n")
    print("rounds | K1 max|z| (key bit, out bit) | K2 max|z| (pair, out bit) | verdict")
    kb, ob = control()
    z1, i1, j1 = zmax(kb, ob)
    print(f"control (key XORed into output): K1 max|z| = {z1:.1f} -> {'flagged, test works' if z1 > FLAG else 'NOT FLAGGED, test is blind'}")
    for rounds in (1, 2, 3, 4, 5, 6, 8, 20):
        kb, ob = keystream(rounds)
        z1, i1, j1 = zmax(kb, ob)
        pairs = RNG.integers(0, 256, size=(512, 2))
        pairs = pairs[pairs[:, 0] != pairs[:, 1]]
        xb = kb[:, pairs[:, 0]] ^ kb[:, pairs[:, 1]]
        z2, i2, j2 = zmax(xb, ob)
        flagged = "LEAK" if max(z1, z2) > FLAG else "none"
        print(f"  {rounds:>2}   | {z1:6.2f} ({i1:>3},{j1:>3})           | {z2:6.2f} ({i2:>3},{j2:>3})         | {flagged}", flush=True)


if __name__ == "__main__":
    main()
