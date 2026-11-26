"""The JSON and Rust copies of the test vectors must match python/tests/vectors.py.

Skipped when the package is tested outside the monorepo (for example from an sdist).
"""

import importlib.util
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
TOOL_PATH = ROOT / "tools" / "sync_vectors.py"

pytestmark = pytest.mark.skipif(not JSON_PATH.exists(), reason="not running inside the monorepo")


def _tool():
    spec = importlib.util.spec_from_file_location("sync_vectors", TOOL_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_json_vectors_match():
    data = json.loads(JSON_PATH.read_text(encoding="utf-8"))
    assert data["permutationZeroState"] == vectors.PERMUTATION_ZERO_STATE
    assert data["aead"] == vectors.AEAD_VECTORS
    assert data["password"] == vectors.PASSWORD_VECTORS
    assert JSON_PATH.read_text(encoding="utf-8") == json.dumps(_tool().as_json(), indent=2, ensure_ascii=False) + "\n"


def test_rust_vectors_are_up_to_date():
    assert RUST_PATH.read_text(encoding="utf-8") == _tool().as_rust(), "run: python tools/sync_vectors.py"
