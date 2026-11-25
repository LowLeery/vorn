"""Diffusion / avalanche analysis for the Vorn-P permutation and the Vorn-2 AEAD.

Usage:  python analysis/avalanche.py        (needs numpy)

Part 1  flip each of the 512 input bits of random states, count output bit flips after
        r rounds. Ideal: mean Hamming distance 256, every (input bit, output bit) pair
        flipping with probability 0.5. A random function gives max |z| around 5.
Part 2  same idea on the AEAD: flip key, nonce, associated-data and plaintext bits and
        compare tag / ciphertext.
"""

import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vorn import core  # noqa: E402

RNG = np.random.default_rng(20261125)


def bits(buf: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(buf, dtype=np.uint8))


def perm(buf: bytes, rounds: int) -> bytes:
    st = bytearray(buf)
    core._permute(st, rounds)
    return bytes(st)


def permutation_avalanche(rounds: int, samples: int):
    flips = np.zeros((512, 512), dtype=np.int64)
    for _ in range(samples):
        base = RNG.bytes(64)
        out0 = bits(perm(base, rounds))
        for i in range(512):
            m = bytearray(base)
            m[i // 8] ^= 0x80 >> (i % 8)
            flips[i] += out0 ^ bits(perm(bytes(m), rounds))
    mean_hd = flips.sum() / (samples * 512)
    per_input = flips.sum(axis=1) / samples
    z = np.abs(flips - samples / 2) / (np.sqrt(samples) / 2)
    return mean_hd, per_input.min(), per_input.max(), z.max(), int((z > 4).sum())


def hd_fraction(a: bytes, b: bytes) -> float:
    return float((bits(a) ^ bits(b)).sum()) / (8 * len(a))


def aead_avalanche(trials: int):
    """Flip single input bits of seal(); report Hamming-distance fraction of the outputs."""
    results = {}
    classes = {
        "key bit -> tag": ("key", 256, "tag"),
        "nonce bit -> tag": ("nonce", 128, "tag"),
        "aad bit -> tag": ("aad", 256, "tag"),
        "plaintext bit (block 0) -> ciphertext block 1": ("pt", 256, "ct1"),
        "plaintext bit (block 0) -> tag": ("pt", 256, "tag"),
        "plaintext bit (block 0) -> ciphertext block 0 (expect 1 bit)": ("pt", 256, "ct0"),
    }
    for label, (field, nbits, target) in classes.items():
        fr = []
        for _ in range(trials):
            key, nonce = RNG.bytes(32), RNG.bytes(16)
            aad, pt = RNG.bytes(32), RNG.bytes(96)
            base = core.seal(key, nonce, pt, aad)
            for i in range(nbits):
                k, n, a, p = bytearray(key), bytearray(nonce), bytearray(aad), bytearray(pt)
                tgt = {"key": k, "nonce": n, "aad": a, "pt": p}[field]
                tgt[i // 8] ^= 0x80 >> (i % 8)
                alt = core.seal(bytes(k), bytes(n), bytes(p), bytes(a))
                sl = {"tag": slice(-16, None), "ct1": slice(32, 64), "ct0": slice(0, 32)}[target]
                fr.append(hd_fraction(base[sl], alt[sl]))
        results[label] = (float(np.mean(fr)), float(np.min(fr)), float(np.max(fr)))
    return results


def main():
    print("PART 1: Vorn-P permutation avalanche (512-bit state)")
    print("rounds | mean HD (ideal 256) | per-input-bit mean HD min..max | max |z| | cells |z|>4")
    samples = 96
    for rounds in (1, 2, 3, 4, 5, 6, 8, 10, 12, 20):
        t = time.time()
        mean_hd, lo, hi, zmax, over4 = permutation_avalanche(rounds, samples)
        print(f"{rounds:6d} | {mean_hd:19.2f} | {lo:7.2f} .. {hi:7.2f}            | {zmax:6.2f} | {over4:6d}"
              f"   ({time.time() - t:.0f}s)")
    print("(random-function reference: max |z| about 4.9-5.3, about 16 cells above 4)\n")

    print("PART 2: Vorn-2 AEAD single-bit avalanche (fraction of output bits that change, ideal 0.5)")
    for label, (mean, lo, hi) in aead_avalanche(trials=6).items():
        print(f"{label:62s} mean {mean:.4f}  min {lo:.3f}  max {hi:.3f}")


if __name__ == "__main__":
    main()
