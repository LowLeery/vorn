import math
from collections import Counter

import pytest

from vorn import VornError, decrypt, encrypt

N = 1024  # testlerde scrypt'i hızlandırmak için


def test_roundtrip_text():
    password = "secret-key-material"
    msg = "Vorn protocol payload verification: 257-904"
    ct = encrypt(msg, password, _scrypt_n=N)
    assert decrypt(ct, password, _scrypt_n=N).decode("utf-8") == msg


def test_roundtrip_unicode():
    password = "şifre-ğüişöç"
    msg = "Merhaba dünya! 你好 🌍"
    ct = encrypt(msg, password, _scrypt_n=N)
    assert decrypt(ct, password, _scrypt_n=N).decode("utf-8") == msg


def test_roundtrip_binary():
    password = "binary-stream-key"
    raw = bytes(range(256))
    ct = encrypt(raw, password, _scrypt_n=N)
    assert decrypt(ct, password, _scrypt_n=N) == raw


def test_empty_input():
    password = "empty-payload-key"
    ct = encrypt(b"", password, _scrypt_n=N)
    assert len(ct) == 144
    assert decrypt(ct, password, _scrypt_n=N) == b""


def test_nonce_uniqueness():
    password = "repeat-test-key"
    ct1 = encrypt("constant message", password, _scrypt_n=N)
    ct2 = encrypt("constant message", password, _scrypt_n=N)
    assert ct1 != ct2


def test_tamper_detection():
    password = "integrity-test-key"
    ct = encrypt("authenticated command", password, _scrypt_n=N)
    corrupted = ct[:64] + ("0" if ct[64] != "0" else "1") + ct[65:]
    with pytest.raises(VornError):
        decrypt(corrupted, password, _scrypt_n=N)


def test_wrong_password():
    ct = encrypt("classified data", "alpha-key", _scrypt_n=N)
    with pytest.raises(VornError):
        decrypt(ct, "beta-key", _scrypt_n=N)


def test_empty_password():
    with pytest.raises(VornError):
        encrypt("x", "", _scrypt_n=N)


@pytest.mark.parametrize("bad", ["", "123", "abc" * 60, "1" * 145, "١" * 144])
def test_malformed_input(bad):
    with pytest.raises(VornError):
        decrypt(bad, "any-key", _scrypt_n=N)


def test_block_entropy():
    ct = encrypt(b"\x00" * 2048, "entropy-test-key", _scrypt_n=N)[48:-96]
    blocks = [int(ct[i : i + 3]) for i in range(0, len(ct), 3)]
    counts = Counter(blocks)
    total = len(blocks)
    entropy = -sum((cnt / total) * math.log2(cnt / total) for cnt in counts.values())
    assert entropy > 5.0
