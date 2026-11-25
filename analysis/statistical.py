"""NIST SP 800-22 style randomness checks on Vorn-2 output streams.

Usage:  python analysis/statistical.py      (needs numpy)

Implements five tests from SP 800-22 / classic practice: frequency (monobit), block
frequency (M=128), runs, cumulative sums (forward) and a byte chi-square. This is NOT the
official NIST STS and passing these tests is NOT evidence of security: weak generators
pass them too. They only catch gross statistical defects.
"""

import math
import sys
from pathlib import Path

import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from vorn import core  # noqa: E402

ALPHA = 0.01


# ---------------------------------------------------------------- special functions
def igamc(a: float, x: float) -> float:
    """Regularised upper incomplete gamma function Q(a, x)."""
    if x <= 0:
        return 1.0
    log_pref = -x + a * math.log(x) - math.lgamma(a)
    if x < a + 1:
        ap, s = a, 1.0 / a
        d = s
        for _ in range(100000):
            ap += 1
            d *= x / ap
            s += d
            if abs(d) < abs(s) * 1e-16:
                break
        return 1.0 - s * math.exp(log_pref)
    tiny = 1e-300
    b = x + 1 - a
    c = 1 / tiny
    d = 1 / b
    h = d
    for i in range(1, 100000):
        an = -i * (i - a)
        b += 2
        d = an * d + b
        d = tiny if abs(d) < tiny else d
        c = b + an / c
        c = tiny if abs(c) < tiny else c
        d = 1 / d
        delta = d * c
        h *= delta
        if abs(delta - 1) < 1e-16:
            break
    return math.exp(log_pref) * h


def phi(x: float) -> float:
    return 0.5 * math.erfc(-x / math.sqrt(2))


# ---------------------------------------------------------------- tests (input: np.uint8 array of bits)
def monobit(b):
    n = len(b)
    s = abs(int(b.sum()) * 2 - n)
    return math.erfc(s / math.sqrt(n) / math.sqrt(2))


def block_frequency(b, m=128):
    nb = len(b) // m
    pi = b[: nb * m].reshape(nb, m).mean(axis=1)
    chi = 4.0 * m * float(((pi - 0.5) ** 2).sum())
    return igamc(nb / 2, chi / 2)


def runs(b):
    n = len(b)
    pi = float(b.mean())
    if abs(pi - 0.5) >= 2 / math.sqrt(n):
        return 0.0
    v = 1 + int((b[1:] != b[:-1]).sum())
    return math.erfc(abs(v - 2 * n * pi * (1 - pi)) / (2 * math.sqrt(2 * n) * pi * (1 - pi)))


def cumulative_sums(b):
    n = len(b)
    x = b.astype(np.int64) * 2 - 1
    z = int(np.abs(np.cumsum(x)).max())
    sq = math.sqrt(n)
    s1 = sum(
        phi((4 * k + 1) * z / sq) - phi((4 * k - 1) * z / sq)
        for k in range(int((-n / z + 1) // 4), int((n / z - 1) // 4) + 1)
    )
    s2 = sum(
        phi((4 * k + 3) * z / sq) - phi((4 * k + 1) * z / sq)
        for k in range(int((-n / z - 3) // 4), int((n / z - 1) // 4) + 1)
    )
    return 1.0 - s1 + s2


def byte_chi_square(raw: bytes):
    counts = np.bincount(np.frombuffer(raw, dtype=np.uint8), minlength=256)
    e = len(raw) / 256
    chi = float(((counts - e) ** 2 / e).sum())
    return igamc(127.5, chi / 2)


TESTS = (
    ("monobit", lambda raw, b: monobit(b)),
    ("block-frequency", lambda raw, b: block_frequency(b)),
    ("runs", lambda raw, b: runs(b)),
    ("cumulative-sums", lambda raw, b: cumulative_sums(b)),
    ("byte-chi-square", lambda raw, b: byte_chi_square(raw)),
)


# ---------------------------------------------------------------- streams
def stream_long_zero_message(nbytes):
    ct = core.seal(bytes(32), bytes(16), bytes(nbytes), b"")
    return ct[:-16]


def stream_counter_nonces(count):
    key = bytes(range(32))
    return b"".join(
        core.seal(key, i.to_bytes(16, "little"), bytes(64), b"")[:-16] for i in range(count)
    )


def stream_counter_keys(count):
    return b"".join(
        core.seal(i.to_bytes(32, "little"), bytes(16), bytes(64), b"")[:-16] for i in range(count)
    )


def stream_tags_counter_nonces(count):
    key = bytes(range(32))
    return b"".join(core.seal(key, i.to_bytes(16, "little"), b"", b"")[-16:] for i in range(count))


STREAMS = (
    ("ciphertext of 512 KiB zero message (single key/nonce)", lambda: stream_long_zero_message(512 * 1024)),
    ("ciphertext, 8192 messages with counter nonces", lambda: stream_counter_nonces(8192)),
    ("ciphertext, 8192 messages with counter keys", lambda: stream_counter_keys(8192)),
    ("tags of 16384 empty messages with counter nonces", lambda: stream_tags_counter_nonces(16384)),
)


def main():
    failures = 0
    total = 0
    for name, make in STREAMS:
        raw = make()
        b = np.unpackbits(np.frombuffer(raw, dtype=np.uint8))
        print(f"\n{name}  ({len(raw)} bytes, {len(b)} bits)")
        for tname, fn in TESTS:
            p = fn(raw, b)
            ok = p >= ALPHA
            total += 1
            failures += not ok
            print(f"  {tname:16s} p = {p:.4f}  {'PASS' if ok else 'FAIL'}")
    print(f"\n{total - failures}/{total} tests passed at alpha = {ALPHA}")
    print("(with alpha = 0.01 about 1 in 100 tests fails by chance even for ideal random data)")


if __name__ == "__main__":
    main()
