"""The JSON and Rust copies of the test vectors must match python/tests/vectors.py.

Skipped when the package is tested outside the monorepo (for example from an sdist).
"""

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
sys.path.insert(0, str(HERE))

import vectors  # noqa: E402

JSON_PATH = ROOT / "vectors" / "vectors.json"
RUST_PATH = ROOT / "rust" / "tests" / "vectors.rs"

pytestmark = pytest.mark.skipif(not JSON_PATH.exists(), reason="not running inside the monorepo")


def test_json_vectors_match():
    data = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert data["permutationZeroState"] == vectors.PERMUTATION_ZERO_STATE
    assert data["aead"] == vectors.AEAD_VECTORS
    assert data["password"] == vectors.PASSWORD_VECTORS


def test_rust_vectors_match():
    text = RUST_PATH.read_text(encoding="utf-8")
    assert vectors.PERMUTATION_ZERO_STATE in text
    for v in vectors.AEAD_VECTORS:
        for field in ("key", "nonce", "aad", "pt", "out"):
            assert f'"{v[field]}"' in text or v[field] == ""
