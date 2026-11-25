import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

import reference  # noqa: E402
import vectors  # noqa: E402

from vorn import VornError, core, decrypt, encrypt, seal, unseal  # noqa: E402

LOG_N = 4  # tiny scrypt cost, tests only


# ------------------------------------------------------------ known answers
def test_permutation_known_answer():
    st = bytearray(64)
    core._permute(st)
    assert bytes(st).hex() == vectors.PERMUTATION_ZERO_STATE


@pytest.mark.parametrize("v", vectors.AEAD_VECTORS)
def test_aead_known_answer(v):
    key, nonce = bytes.fromhex(v["key"]), bytes.fromhex(v["nonce"])
    aad, pt = bytes.fromhex(v["aad"]), bytes.fromhex(v["pt"])
    assert seal(key, nonce, pt, aad).hex() == v["out"]
    assert unseal(key, nonce, bytes.fromhex(v["out"]), aad) == pt


def test_round_constants_are_sqrt_primes():
    # first four SHA-256 initial hash words are the same construction
    assert core._RC[:4] == (0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A)


# ------------------------------------------------------------ cross-check with reference
def test_permutation_matches_reference():
    for _ in range(50):
        raw = os.urandom(64)
        fast = bytearray(raw)
        core._permute(fast)
        slow = list(raw)
        reference.permute(slow)
        assert bytes(fast) == bytes(slow)


@pytest.mark.parametrize("ad_len", [0, 1, 31, 32, 33, 64, 97])
@pytest.mark.parametrize("pt_len", [0, 1, 31, 32, 33, 64, 65, 200])
def test_aead_matches_reference(ad_len, pt_len):
    key, nonce = os.urandom(32), os.urandom(16)
    aad, pt = os.urandom(ad_len), os.urandom(pt_len)
    assert seal(key, nonce, pt, aad) == reference.seal(key, nonce, pt, aad)


# ------------------------------------------------------------ AEAD properties
def test_aead_roundtrip_and_lengths():
    key, nonce = os.urandom(32), os.urandom(16)
    for n in (0, 1, 31, 32, 33, 1000):
        pt = os.urandom(n)
        sealed = seal(key, nonce, pt, b"ad")
        assert len(sealed) == n + 16
        assert unseal(key, nonce, sealed, b"ad") == pt


def test_aead_rejects_every_single_bit_flip():
    key, nonce = os.urandom(32), os.urandom(16)
    sealed = seal(key, nonce, os.urandom(70), b"aad")
    for i in range(len(sealed)):
        for bit in (0, 7):
            bad = bytearray(sealed)
            bad[i] ^= 1 << bit
            with pytest.raises(VornError):
                unseal(key, nonce, bytes(bad), b"aad")


def test_aead_binds_aad_key_nonce():
    key, nonce = os.urandom(32), os.urandom(16)
    sealed = seal(key, nonce, b"payload", b"aad")
    with pytest.raises(VornError):
        unseal(key, nonce, sealed, b"other")
    with pytest.raises(VornError):
        unseal(os.urandom(32), nonce, sealed, b"aad")
    with pytest.raises(VornError):
        unseal(key, os.urandom(16), sealed, b"aad")


def test_aead_rejects_truncation_and_extension():
    key, nonce = os.urandom(32), os.urandom(16)
    sealed = seal(key, nonce, os.urandom(64), b"")
    for bad in (sealed[:-1], sealed[1:], sealed + b"\x00", b"", sealed[:15]):
        with pytest.raises(VornError):
            unseal(key, nonce, bad, b"")


def test_ad_and_message_boundary_is_unambiguous():
    key, nonce = os.urandom(32), os.urandom(16)
    a = seal(key, nonce, b"BBBB", b"AAAA")
    b = seal(key, nonce, b"AAAABBBB", b"")
    c = seal(key, nonce, b"", b"AAAABBBB")
    assert len({a, b, c}) == 3


def test_bad_key_and_nonce_sizes():
    with pytest.raises(VornError):
        seal(b"short", bytes(16), b"x")
    with pytest.raises(VornError):
        seal(bytes(32), b"short", b"x")


# ------------------------------------------------------------ password API
def test_password_roundtrip_text_binary_empty():
    for data in ("merhaba dünya 🌍", bytes(range(256)), b"", "x" * 5000):
        blob = encrypt(data, "pw-ğüşiöç", log_n=LOG_N)
        expected = data.encode() if isinstance(data, str) else data
        assert decrypt(blob, "pw-ğüşiöç") == expected


def test_armor_roundtrip():
    text = encrypt("armored", "pw", log_n=LOG_N, armor=True)
    assert isinstance(text, str) and "=" not in text
    assert decrypt(text, "pw") == b"armored"
    assert decrypt("  " + text + "\n", "pw") == b"armored"


def test_user_aad():
    blob = encrypt("data", "pw", aad=b"context-1", log_n=LOG_N)
    assert decrypt(blob, "pw", aad=b"context-1") == b"data"
    with pytest.raises(VornError):
        decrypt(blob, "pw", aad=b"context-2")


def test_wrong_and_empty_password():
    blob = encrypt("secret", "right", log_n=LOG_N)
    with pytest.raises(VornError):
        decrypt(blob, "wrong")
    with pytest.raises(VornError):
        encrypt("x", "", log_n=LOG_N)
    with pytest.raises(VornError):
        decrypt(blob, "")


def test_every_byte_of_the_blob_is_authenticated():
    blob = encrypt("authenticated", "pw", log_n=LOG_N)
    for i in range(len(blob)):
        bad = bytearray(blob)
        bad[i] ^= 0x01
        with pytest.raises(VornError):
            decrypt(bytes(bad), "pw")


def test_fresh_salt_and_nonce_each_time():
    a = encrypt("same", "pw", log_n=LOG_N)
    b = encrypt("same", "pw", log_n=LOG_N)
    assert a != b
    assert a[7:23] != b[7:23] and a[23:39] != b[23:39]


@pytest.mark.parametrize("bad", [b"", b"VRN2", b"x" * 80, "!!!notbase64!!!", "A" * 10])
def test_malformed_input(bad):
    with pytest.raises(VornError):
        decrypt(bad, "pw")


def test_unreasonable_scrypt_parameters_rejected():
    blob = bytearray(encrypt("x", "pw", log_n=LOG_N))
    blob[4] = 30  # would demand terabytes of memory
    with pytest.raises(VornError):
        decrypt(bytes(blob), "pw")
    with pytest.raises(VornError):
        encrypt("x", "pw", log_n=30)


def test_large_message():
    key, nonce = os.urandom(32), os.urandom(16)
    data = os.urandom(200_000)
    assert unseal(key, nonce, seal(key, nonce, data, b""), b"") == data
