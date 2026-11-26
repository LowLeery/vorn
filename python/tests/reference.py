"""Slow, independently structured reference implementation of Vorn-2.

It follows SPEC.md literally (word lists, byte-at-a-time duplex) and shares no code
with vorn/core.py. It exists only so the tests can cross-check the fast implementation.
"""

M = 0xFFFFFFFF


def _primes(count):
    out, n = [], 2
    while len(out) < count:
        if all(n % q != 0 for q in range(2, int(n**0.5) + 1)):
            out.append(n)
        n += 1
    return out


def _isqrt_frac32(p):
    # floor(frac(sqrt(p)) * 2**32) using plain integer Newton iteration
    target = p << 64
    x = 1 << 40
    while True:
        y = (x + target // x) // 2
        if y >= x:
            break
        x = y
    while x * x > target:
        x -= 1
    while (x + 1) * (x + 1) <= target:
        x += 1
    return x % (1 << 32)


PR = _primes(20)
RC = [_isqrt_frac32(p) for p in PR]
LANE = [p % 16 for p in PR]


def rotl(v, n):
    return ((v << n) & M) | (v >> (32 - n))


def quarter(s, a, b, c, d):
    s[a] = (s[a] + s[b]) & M
    s[d] = rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & M
    s[b] = rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & M
    s[d] = rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & M
    s[b] = rotl(s[b] ^ s[c], 7)


def permute(st):
    """st: list of 64 byte values."""
    s = [int.from_bytes(bytes(st[4 * i : 4 * i + 4]), "little") for i in range(16)]
    for r in range(20):
        s[LANE[r]] ^= RC[r]
        if r % 2 == 0:
            for i in range(4):
                quarter(s, i, i + 4, i + 8, i + 12)
        else:
            for i in range(4):
                quarter(s, i, 4 + (i + 1) % 4, 8 + (i + 2) % 4, 12 + (i + 3) % 4)
    out = []
    for w in s:
        out.extend(w.to_bytes(4, "little"))
    st[:] = out


def seal(key, nonce, plaintext, aad=b""):
    st = list(b"Vorn-2 AEAD v0.2" + nonce + key)
    permute(st)
    pos = 0
    for byte in aad:
        st[pos] ^= byte
        pos += 1
        if pos == 32:
            permute(st)
            pos = 0
    st[pos] ^= 0x80
    permute(st)
    st[63] ^= 1
    pos = 0
    ct = []
    for byte in plaintext:
        c = byte ^ st[pos]
        st[pos] = c
        ct.append(c)
        pos += 1
        if pos == 32:
            permute(st)
            pos = 0
    st[pos] ^= 0x80
    for i in range(32):
        st[32 + i] ^= key[i]
    permute(st)
    tag = [st[48 + i] ^ key[16 + i] for i in range(16)]
    return bytes(ct + tag)
