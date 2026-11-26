"""Vorn-2: an experimental duplex-sponge AEAD built on a 512-bit ARX permutation.

EXPERIMENTAL. Not reviewed by third parties. Do not use to protect real secrets.
See SPEC.md for the full specification and ANALYSIS.md for the analysis done so far.
"""

import base64
import binascii
import hashlib
import hmac
import secrets
import struct
from math import isqrt

__version__ = "0.2.4"
__all__ = ["encrypt", "decrypt", "seal", "unseal", "VornError", "__version__"]

# ---------------------------------------------------------------- parameters
MASK = 0xFFFFFFFF
STATE_LEN = 64  # 512-bit state = 16 little-endian 32-bit words
RATE = 32  # bytes absorbed/squeezed per permutation call
KEY_LEN = 32
NONCE_LEN = 16
TAG_LEN = 16
SALT_LEN = 16
ROUNDS = 20
LABEL = b"Vorn-2 AEAD v0.2"  # 16 bytes, domain label placed in the state at init
MAGIC = b"VRN2"
HEADER_LEN = len(MAGIC) + 3 + SALT_LEN + NONCE_LEN  # magic, log_n, r, p, salt, nonce
DEFAULT_LOG_N = 16
MAX_SCRYPT_BYTES = 1 << 29  # refuse scrypt settings that would need more than 512 MiB

assert len(LABEL) == 16


class VornError(Exception):
    """Raised for malformed input, wrong password, or failed authentication."""


# ---------------------------------------------------------------- permutation
def _first_primes(count: int) -> tuple:
    primes = []
    n = 2
    while len(primes) < count:
        if all(n % p for p in primes if p * p <= n):
            primes.append(n)
        n += 1
    return tuple(primes)


_PRIMES = _first_primes(ROUNDS)
# Round constants: fractional part of sqrt(prime), top 32 bits.
_RC = tuple(isqrt(p << 64) & MASK for p in _PRIMES)
# Prime hopping: the lane that receives round constant r is (prime_r mod 16).
_LANE = tuple(p % 16 for p in _PRIMES)

_COLUMNS = ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15))
_DIAGONALS = ((0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14))


def _permute(state: bytearray, rounds: int = ROUNDS) -> None:
    """Apply the Vorn-P permutation to a 64-byte state, in place."""
    if not 1 <= rounds <= ROUNDS:
        raise ValueError("rounds out of range")
    s = list(struct.unpack("<16I", state))
    for r in range(rounds):
        s[_LANE[r]] ^= _RC[r]
        for a, b, c, d in _DIAGONALS if r & 1 else _COLUMNS:
            x, y, z, w = s[a], s[b], s[c], s[d]
            x = (x + y) & MASK
            w ^= x
            w = ((w << 16) | (w >> 16)) & MASK
            z = (z + w) & MASK
            y ^= z
            y = ((y << 12) | (y >> 20)) & MASK
            x = (x + y) & MASK
            w ^= x
            w = ((w << 8) | (w >> 24)) & MASK
            z = (z + w) & MASK
            y ^= z
            y = ((y << 7) | (y >> 25)) & MASK
            s[a], s[b], s[c], s[d] = x, y, z, w
    state[:] = struct.pack("<16I", *s)


# ---------------------------------------------------------------- duplex AEAD
def _xor(a, b) -> bytes:
    n = len(a)
    return (int.from_bytes(a, "little") ^ int.from_bytes(b[:n], "little")).to_bytes(n, "little")


def _run(key: bytes, nonce: bytes, aad: bytes, data: bytes, decrypting: bool, rounds: int = ROUNDS):
    # initial state: label and nonce in the rate half, the whole key in the capacity half
    st = bytearray(LABEL + nonce + key)
    _permute(st, rounds)

    # associated data, always followed by one padded block (pad10*)
    i = 0
    while len(aad) - i >= RATE:
        st[:RATE] = _xor(st[:RATE], aad[i : i + RATE])
        _permute(st, rounds)
        i += RATE
    last = aad[i:] + b"\x80"
    st[: len(last)] = _xor(st[: len(last)], last)
    _permute(st, rounds)

    st[STATE_LEN - 1] ^= 0x01  # domain separation: associated data -> message

    # message: the rate part of the state is overwritten with ciphertext
    out = bytearray()
    i = 0
    n = len(data)
    while n - i >= RATE:
        blk = bytes(data[i : i + RATE])
        o = _xor(blk, st[:RATE])
        st[:RATE] = blk if decrypting else o
        _permute(st, rounds)
        out += o
        i += RATE
    rem = bytes(data[i:])
    m = len(rem)
    o = _xor(rem, st[:m])
    st[:m] = rem if decrypting else o
    st[m] ^= 0x80
    out += o

    # finalisation: key goes into the capacity, tag is read from the last 16 bytes
    st[RATE:STATE_LEN] = _xor(st[RATE:STATE_LEN], key)
    _permute(st, rounds)
    tag = _xor(st[48:64], key[16:32])
    return bytes(out), tag


def _check_key_nonce(key: bytes, nonce: bytes) -> None:
    if not isinstance(key, (bytes, bytearray)) or len(key) != KEY_LEN:
        raise VornError("Key must be exactly 32 bytes.")
    if not isinstance(nonce, (bytes, bytearray)) or len(nonce) != NONCE_LEN:
        raise VornError("Nonce must be exactly 16 bytes.")


def seal(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> bytes:
    """Low-level AEAD. Returns ciphertext || 16-byte tag. Never reuse a (key, nonce) pair."""
    _check_key_nonce(key, nonce)
    ct, tag = _run(bytes(key), bytes(nonce), bytes(aad), bytes(plaintext), False)
    return ct + tag


def unseal(key: bytes, nonce: bytes, sealed: bytes, aad: bytes = b"") -> bytes:
    """Inverse of seal(). Raises VornError if authentication fails."""
    _check_key_nonce(key, nonce)
    if len(sealed) < TAG_LEN:
        raise VornError("Malformed ciphertext.")
    ct, tag = bytes(sealed[:-TAG_LEN]), bytes(sealed[-TAG_LEN:])
    pt, expected = _run(bytes(key), bytes(nonce), bytes(aad), ct, True)
    if not hmac.compare_digest(tag, expected):
        raise VornError("Authentication failed: wrong password or modified data.")
    return pt


# ---------------------------------------------------------------- password API
def _check_scrypt_params(log_n: int, r: int, p: int) -> None:
    if not (1 <= log_n <= 24 and 1 <= r <= 32 and 1 <= p <= 16):
        raise VornError("Unsupported scrypt parameters.")
    if 128 * r * (1 << log_n) > MAX_SCRYPT_BYTES:
        raise VornError("Unsupported scrypt parameters.")


def _kdf(password, salt: bytes, log_n: int, r: int, p: int) -> bytes:
    if isinstance(password, str):
        password = password.encode("utf-8")
    if not password:
        raise VornError("Password must not be empty.")
    n = 1 << log_n
    return hashlib.scrypt(
        bytes(password),
        salt=salt,
        n=n,
        r=r,
        p=p,
        dklen=KEY_LEN,
        maxmem=2 * 128 * r * n + (1 << 24),
    )


def _as_bytes(value, name: str) -> bytes:
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value)
    raise VornError(f"{name} must be bytes or str.")


def encrypt(data, password, *, aad=b"", log_n: int = DEFAULT_LOG_N, r: int = 8, p: int = 1, armor: bool = False):
    """Encrypt data with a password. Returns bytes, or a base64url str when armor=True.

    The blob is: MAGIC | log_n | r | p | salt | nonce | ciphertext | tag.
    The whole header and any extra `aad` are authenticated.
    """
    _check_scrypt_params(log_n, r, p)
    data = _as_bytes(data, "data")
    aad = _as_bytes(aad, "aad")
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    header = MAGIC + bytes([log_n, r, p]) + salt + nonce
    key = _kdf(password, salt, log_n, r, p)
    blob = header + seal(key, nonce, data, header + aad)
    if armor:
        return base64.urlsafe_b64encode(blob).decode("ascii").rstrip("=")
    return blob


def decrypt(blob, password, *, aad=b"") -> bytes:
    """Decrypt output of encrypt() (bytes or the armored base64url str)."""
    if isinstance(blob, str):
        text = blob.strip()
        try:
            blob = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
        except (binascii.Error, ValueError) as exc:
            raise VornError("Malformed ciphertext.") from exc
    blob = bytes(blob)
    aad = _as_bytes(aad, "aad")
    if len(blob) < HEADER_LEN + TAG_LEN or blob[: len(MAGIC)] != MAGIC:
        raise VornError("Malformed ciphertext.")
    log_n, r, p = blob[4], blob[5], blob[6]
    _check_scrypt_params(log_n, r, p)
    salt = blob[7 : 7 + SALT_LEN]
    nonce = blob[7 + SALT_LEN : HEADER_LEN]
    header = blob[:HEADER_LEN]
    key = _kdf(password, salt, log_n, r, p)
    return unseal(key, nonce, blob[HEADER_LEN:], header + aad)
