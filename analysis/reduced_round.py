"""Reduced-round distinguisher experiments on Vorn-P and Vorn-2.

Usage:  python analysis/reduced_round.py        (needs numpy, about 2-4 minutes)

For r = 1..8 rounds (and the full 20) this looks for statistical weaknesses that would let an
attacker distinguish the permutation from a random one:

  E1  differential bias   single-bit input difference -> bias of each output-difference bit
  E2  linear bias         correlation of low-weight input masks with single output bits
                          (INCONCLUSIVE: too weak to detect even 1 round, see output)
  E3  integral / cube     XOR of outputs over a 2^k cube of inputs (zero-sum property)
  E4  AEAD nonce          one-bit nonce difference -> difference of first ciphertext block / tag

Every number is a z-score: deviation from the random expectation divided by its standard
deviation. Over many tested cells the largest |z| of a *random* function is about 4.5 to 5.3,
so only values clearly above ~6 are flagged. These are distinguishers, not key recovery.
"""

import sys
import time
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
from vorn import core  # noqa: E402

RNG = np.random.default_rng(20261125)
COLUMNS = ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15))
DIAGONALS = ((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14))
ROUND_LIST = (1, 2, 3, 4, 5, 6, 8, 20)
FLAG = 6.0


def rotl(x, n):
    return (x << np.uint32(n)) | (x >> np.uint32(32 - n))


def vperm(state: np.ndarray, rounds: int) -> np.ndarray:
    """Vectorised Vorn-P on an (N, 16) uint32 array."""
    s = [state[:, i].copy() for i in range(16)]
    for r in range(rounds):
        s[core._LANE[r]] ^= np.uint32(core._RC[r])
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


def bits(x: np.ndarray) -> np.ndarray:
    """(N, 16) uint32 -> (N, 512) uint8, column index = word*32 + bit (little-endian)."""
    return np.unpackbits(np.ascontiguousarray(x).view(np.uint8), axis=1, bitorder="little")


def random_states(n: int) -> np.ndarray:
    return RNG.integers(0, 2**32, size=(n, 16), dtype=np.uint32)


def flip(state: np.ndarray, k: int) -> np.ndarray:
    out = state.copy()
    out[:, k // 32] ^= np.uint32(1 << (k % 32))
    return out


def self_check():
    raw = RNG.bytes(64 * 5)
    arr = np.frombuffer(raw, dtype="<u4").reshape(5, 16).copy()
    for rounds in (1, 7, 20):
        fast = vperm(arr, rounds)
        for i in range(5):
            st = bytearray(raw[64 * i : 64 * i + 64])
            core._permute(st, rounds)
            assert bytes(st) == fast[i].astype("<u4").tobytes()


# ---------------------------------------------------------------- E1 / E2
def e1_differential(rounds: int, n: int = 16384):
    base = random_states(n)
    out0 = vperm(base, rounds)
    zmax_all = zmax_rate = 0.0
    sigma = 0.5 / np.sqrt(n)
    for k in range(512):
        d = bits(out0 ^ vperm(flip(base, k), rounds)).mean(axis=0)
        z = np.abs(d - 0.5) / sigma
        zmax_all = max(zmax_all, float(z.max()))
        if k < 256:  # input difference confined to the rate (attacker controlled)
            zmax_rate = max(zmax_rate, float(z[:256].max()))
    return zmax_all, zmax_rate


def e2_linear(rounds: int, n: int = 1 << 16):
    base = random_states(n)
    x = bits(base).astype(np.float32) * 2 - 1
    y = bits(vperm(base, rounds)).astype(np.float32) * 2 - 1
    corr = (x.T @ y) / np.float32(n)
    z = np.abs(corr) * np.sqrt(n)
    return float(z.max()), float(z[:256, :256].max())


def e2b_linear_weight2(rounds: int, n: int = 16384):
    """Input masks of weight 2 (all pairs among the 256 rate bits) vs single output bits.

    Weight-1 masks are blind to the main linear structure of ARX (the lowest bit of an
    addition is the XOR of two bits), so pairs are needed. 32640 masks x 256 outputs.
    """
    base = random_states(n)
    x = bits(base)[:, :256].astype(np.float32) * 2 - 1
    y = bits(vperm(base, rounds))[:, :256].astype(np.float32) * 2 - 1
    zmax = 0.0
    for i in range(255):
        feat = x[:, i : i + 1] * x[:, i + 1 :]
        corr = (feat.T @ y) / np.float32(n)
        zmax = max(zmax, float(np.abs(corr).max()) * float(np.sqrt(n)))
    return zmax


# ---------------------------------------------------------------- E3
def e3_integral(rounds: int, cube_bits, trials: int = 48):
    k = len(cube_bits)
    idx = np.arange(1 << k, dtype=np.uint64)
    zeros = np.zeros(512)
    for _ in range(trials):
        base = np.tile(random_states(1), (1 << k, 1))
        for j, pos in enumerate(cube_bits):
            sel = ((idx >> np.uint64(j)) & np.uint64(1)).astype(np.uint32)
            base[:, pos // 32] ^= sel << np.uint32(pos % 32)
        out = vperm(base, rounds)
        total = np.bitwise_xor.reduce(out, axis=0)  # (16,) XOR over the cube
        zeros += 1 - bits(total[None, :])[0]
    z = np.abs(zeros - trials / 2) / (0.5 * np.sqrt(trials))
    return float(z.max()), int((zeros == trials).sum())


# ---------------------------------------------------------------- E4
def e4_aead_nonce(rounds: int, samples: int = 256):
    key_len, nonce_len = 32, 16
    zmax = 0.0
    sigma = 0.5 / np.sqrt(samples)
    counts = np.zeros((128, 48 * 8))  # 32 ct bytes + 16 tag bytes
    for _ in range(samples):
        key, nonce = RNG.bytes(key_len), RNG.bytes(nonce_len)
        base_ct, base_tag = core._run(key, nonce, b"", bytes(32), False, rounds)
        base = np.unpackbits(np.frombuffer(base_ct + base_tag, dtype=np.uint8))
        for b in range(128):
            n2 = bytearray(nonce)
            n2[b // 8] ^= 0x80 >> (b % 8)
            ct, tag = core._run(key, bytes(n2), b"", bytes(32), False, rounds)
            counts[b] += base ^ np.unpackbits(np.frombuffer(ct + tag, dtype=np.uint8))
    z = np.abs(counts / samples - 0.5) / sigma
    return float(z.max())


def tag(z):
    return "  <-- distinguisher" if z > FLAG else ""


def main():
    self_check()
    print("Vorn-P reduced-round experiments (z-scores; random permutation: largest |z| about 4.5-5.3)")
    print(f"flag threshold: |z| > {FLAG}\n")

    print("E1 differential bias: 512 single-bit input differences x 512 output bits, 16384 pairs each")
    print("rounds | max |z| all bits | max |z| rate-only (diff and output in the rate)")
    for r in ROUND_LIST:
        t = time.time()
        a, b = e1_differential(r)
        print(f"{r:6d} | {a:16.2f} | {b:10.2f}{tag(max(a, b))}   ({time.time() - t:.0f}s)")

    print("\nE2 linear bias, single-bit masks: 512 x 512 input/output bits, 65536 samples")
    print("INCONCLUSIVE: these masks do not detect even 1 round (which is trivially weak), so this")
    print("test is blind for ARX and gives NO evidence of linear resistance.")
    print("rounds | max |z| all bits | max |z| rate-only")
    for r in ROUND_LIST:
        a, b = e2_linear(r)
        print(f"{r:6d} | {a:16.2f} | {b:10.2f}{tag(max(a, b))}")

    print("\nE2b linear bias, weight-2 input masks (all 32640 pairs of rate bits) x 256 rate output bits, 16384 samples")
    print("(8.4 million cells: a random function gives a largest |z| of about 5.5-5.9; flag threshold 7)")
    print("INCONCLUSIVE as well: weight-2 masks also miss 1 round, because carries spread the linear")
    print("structure over more input bits. A real linear analysis needs trail search (future work).")
    print("rounds | max |z|")
    for r in ROUND_LIST:
        t = time.time()
        z = e2b_linear_weight2(r)
        print(f"{r:6d} | {z:7.2f}{'  <-- distinguisher' if z > 7 else ''}   ({time.time() - t:.0f}s)")

    cubes = {
        "14 low bits of word 0": list(range(14)),
        "14 bits spread over rate words 0-7": [w * 32 + 5 * j for j in range(2) for w in range(7)],
    }
    print("\nE3 integral: XOR of all outputs over a 2^14 cube, 48 random bases, 512 output bits")
    print("(z over output bits of 'cube sum = 0' frequency; 'always zero' = output bits that were 0 in all 48 bases)")
    for name, cube in cubes.items():
        print(f"cube: {name}")
        print("rounds | max |z| | output bits always zero")
        for r in ROUND_LIST:
            z, always = e3_integral(r, cube)
            print(f"{r:6d} | {z:7.2f} | {always:5d}{tag(z)}")

    print("\nE4 Vorn-2 AEAD, all internal permutations reduced to r rounds:")
    print("one-bit nonce difference -> first ciphertext block (32 B) and tag (16 B), 256 keys x 128 nonce bits")
    print("rounds | max |z| over 128 x 384 cells")
    for r in (1, 2, 3, 4, 5, 6, 20):
        z = e4_aead_nonce(r)
        print(f"{r:6d} | {z:7.2f}{tag(z)}")


if __name__ == "__main__":
    main()
