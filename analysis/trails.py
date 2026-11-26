"""Differential trail search on Vorn-P (heuristic beam search, no solver needed).

Usage:  python analysis/trails.py            (pure Python, about 5 minutes)

For XOR differences, modular addition is the only non-linear step. Its differential probability
follows Lipmaa and Moriai (2001): for n-bit words, (alpha, beta -> gamma) is possible iff
    eq(alpha<<1, beta<<1, gamma<<1) & (alpha ^ beta ^ gamma ^ (beta<<1)) == 0
and then has probability 2^-w with w = HW(~eq(alpha, beta, gamma) & mask_(n-1)),
eq(x, y, z) = (~x ^ y) & (~x ^ z). Self-check 1 verifies this against brute force for n = 6.

The search starts from a one-bit difference in the rate (the part an attacker controls when
absorbing a message) and runs a beam search over rounds: after every addition only the K
lightest output differences are kept, and after every step only the B lightest states.

WHAT THE NUMBER MEANS. "best weight found" is the weight of the best single trail the beam
found. It is an UPPER bound on the true minimum weight (the real best trail may be lighter), so
it shows what a simple attacker finds; it is NOT a proof that no better trail exists. A trail of
weight w means a differential characteristic with probability 2^-w; with a 256-bit capacity,
w well above 128 gives no exploitable single trail.
"""

import itertools
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "python"))
from vorn import core  # noqa: E402

M32 = 0xFFFFFFFF
COLUMNS = ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15))
NODE_LIMIT = 4000  # per addition and budget stage; keeps dense differences affordable
DIAGONALS = ((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14))


def rotl(x, n, w=32):
    m = (1 << w) - 1
    return ((x << n) | (x >> (w - n))) & m


def eq(x, y, z):
    return ~(x ^ y) & ~(x ^ z)


def lm_weight(a, b, g, n):
    """Lipmaa-Moriai weight of (a, b -> g) over n-bit words, or None if impossible."""
    m = (1 << n) - 1
    if (eq((a << 1) & m, (b << 1) & m, (g << 1) & m) & (a ^ b ^ g ^ ((b << 1) & m))) & m:
        return None
    return bin(~eq(a, b, g) & (m >> 1)).count("1")


def lightest_outputs(a, b, k, n=32, budget=48):
    """Up to k output differences g of the addition with the lowest weight (<= budget).

    Depth-first over g bits, least significant first; validity and weight at bit i depend only
    on bits <= i, so partial assignments can be pruned exactly."""
    found = []
    nodes = [0]

    def dfs(i, g, w):
        nodes[0] += 1
        if w > budget or nodes[0] > NODE_LIMIT:
            return
        if i == n:
            found.append((w, g))
            return
        ai, bi = (a >> i) & 1, (b >> i) & 1
        pa, pb = ((a >> (i - 1)) & 1, (b >> (i - 1)) & 1) if i else (0, 0)
        for gi in (0, 1):
            pg = (g >> (i - 1)) & 1 if i else 0
            e_prev = (1 ^ (pa ^ pb)) & (1 ^ (pa ^ pg)) if i else 1
            if e_prev & (ai ^ bi ^ gi ^ pb):
                continue
            dw = 0 if i == n - 1 else 1 - ((1 ^ (ai ^ bi)) & (1 ^ (ai ^ gi)))
            dfs(i + 1, g | (gi << i), w + dw)

    # tighten the budget progressively so the search stays small
    for bud in (2, 6, 12, 20, 32, budget):
        found.clear()
        nodes[0] = 0
        budget_save = budget
        budget = bud
        dfs(0, 0, 0)
        budget = budget_save
        if len(found) >= k:
            break
    found.sort()
    return found[:k]


def self_check(n=6):
    """Compare lm_weight with exact counts of x+y over all inputs, and the DFS with lm_weight."""
    m = (1 << n) - 1
    bad = 0
    for a, b in itertools.product(range(1 << n), repeat=2):
        counts = {}
        for x in range(1 << n):
            for y in range(1 << n):
                g = (((x ^ a) + (y ^ b)) ^ (x + y)) & m
                counts[g] = counts.get(g, 0) + 1
        for g in range(1 << n):
            w = lm_weight(a, b, g, n)
            exact = counts.get(g, 0)
            if (w is None) != (exact == 0) or (w is not None and exact != (1 << (2 * n)) >> w):
                bad += 1
        best = sorted((lm_weight(a, b, g, n), g) for g in range(1 << n) if lm_weight(a, b, g, n) is not None)
        got = lightest_outputs(a, b, 1, n, budget=2 * n)
        if got and got[0][0] != best[0][0]:
            bad += 1
    return bad


def quarter_round_beam(states, qr, k, beam):
    a, b, c, d = qr
    for step in range(4):
        new = []
        for w, s in states:
            x, y = {0: (a, b), 1: (c, d), 2: (a, b), 3: (c, d)}[step]
            for dw, g in lightest_outputs(s[x], s[y], k):
                t = list(s)
                t[x] = g
                if step == 0:
                    t[d] = rotl(t[d] ^ t[a], 16)
                elif step == 1:
                    t[b] = rotl(t[b] ^ t[c], 12)
                elif step == 2:
                    t[d] = rotl(t[d] ^ t[a], 8)
                else:
                    t[b] = rotl(t[b] ^ t[c], 7)
                new.append((w + dw, tuple(t)))
        new.sort(key=lambda p: p[0])
        seen, states = set(), []
        for w, s in new:
            if s not in seen:
                seen.add(s)
                states.append((w, s))
            if len(states) >= beam:
                break
    return states


def search(start_words, rounds, k=2, beam=60):
    best = []
    for word, bit in start_words:
        s = [0] * 16
        s[word] = 1 << bit
        states = [(0, tuple(s))]
        for r in range(rounds):
            for qr in DIAGONALS if r & 1 else COLUMNS:
                states = quarter_round_beam(states, qr, k, beam)
        best.append(min(w for w, _ in states))
    return min(best), sorted(best)[len(best) // 2]


def main():
    t0 = time.time()
    bad = self_check(6)
    print(f"self-check (n=6, exact counts vs Lipmaa-Moriai vs DFS): {'PASS' if bad == 0 else 'FAIL ' + str(bad)}")
    if bad:
        sys.exit(1)
    starts = [(w, b) for w in range(8) for b in (0, 7, 15, 31)]  # one-bit differences in the rate
    print(f"{len(starts)} one-bit rate starts, beam 60, 2 outputs per addition\n")
    print("rounds | lightest trail found (weight) | median over starts")
    prev = None
    for rounds in (1, 2, 3, 4):
        lo, med = search(starts, rounds)
        print(f"  {rounds:>2}   |  {lo:>4}  (probability 2^-{lo})      | {med}", flush=True)
        prev = lo
    print(f"\n(took {time.time() - t0:.0f} s)")


if __name__ == "__main__":
    main()
