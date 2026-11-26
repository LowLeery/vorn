# Contributing

Contributions of every kind are welcome, especially **cryptanalysis** (see SECURITY.md),
independent implementations, and corrections to the analysis.

## Running the tests

```bash
# Python
cd python && pip install pytest && python -m pytest

# JavaScript (Node 18+)
cd js && npm test

# Rust
cd rust && cargo test && cargo clippy --all-targets -- -D warnings && cargo fmt --check

# Experiments (need numpy; a few minutes in total)
pip install numpy
python analysis/avalanche.py
python analysis/statistical.py
python analysis/reduced_round.py
python analysis/ablation.py
python analysis/prime_roles.py
```

## Test vectors

`python/tests/vectors.py` is the single source of truth. If you change the specification (and
therefore the vectors), regenerate the shared copies and commit them:

```bash
python tools/sync_vectors.py
```

A Python test fails if the JSON and Rust copies drift out of sync.

## Changing the specification

Any change that alters ciphertext or tags makes older data undecryptable. It must come with a
new version number, new test vectors in all three implementations, an updated SPEC.md, and an
explanation in ANALYSIS.md. Do not edit published vectors in place.

## Adding an implementation

Implement SPEC.md, pass every vector in `vectors/vectors.json` (permutation, AEAD, password
container), and open a pull request adding a folder and a row in the README table.

## Style

Small, readable code. Claims in documentation must be backed by a script in `analysis/` or a
test, and anything that is not done yet should be listed as not done.
