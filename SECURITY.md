# Security policy

Vorn is an **experimental research cipher**. It has not been reviewed by third parties and must
not be used to protect real secrets. Because of that, there is no embargo process and no secret
to protect: please report everything **publicly** as a GitHub issue.

## What to report

- Any distinguisher, forgery, key or state recovery, even on reduced rounds or with unrealistic
  data complexity. Please include your method, the number of rounds, the cost, and code if you can.
- Flaws in the specification, for example in the padding, domain separation or key injection.
- Implementation bugs: wrong output, disagreement between the Python, JavaScript and Rust
  implementations, crashes on malformed input, unreasonable resource use.
- Mistakes in the analysis scripts or in the claims in ANALYSIS.md.

## What you can expect

Findings are credited in ANALYSIS.md and the specification is revised in a new version. There
is no bug bounty. Negative results (an attack that fails) are also valuable, please share them.

## Supported versions

Only the latest release. Vorn 0.1.0 was an unrelated, broken construction and must not be used.
