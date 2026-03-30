---
name: cerberus-scout
description: Proof planning and submission skill for cerberus-proof-auditor. Reads confirmed findings from cerberus-detective and produces structured proof plans, PoC specifications, test scaffolds, and submission bundles. Use standalone after cerberus-detective has produced finding confirmations.
---

# cerberus-scout

**Invocable standalone:** YES. Requires `finding_confirmations.json` (and optionally `proof_plans.json`) in `.audit_board/`.

**Inputs:** `finding_confirmations.json`, `proof_plans.json` (if already generated), optional `finding-id`, `finding-title`

## Phases

### Proof Planning
`scripts/plan_proofs.py`

Generates structured proof plans from confirmed findings. Classifies confirmability:
- `confirmable_and_reproducible` — strong source signal, low false-positive risk
- `confirmable_but_weak` — useful signal but significant unknowns
- `interesting_but_unconfirmed` — requires more investigation

Produces harness candidates, transaction sequences, assertions, expected outcomes, and minimum test commands per toolchain (Foundry, Hardhat, Truffle, Brownie, Anchor, bare).

**Outputs:** `proof_plans.json`

### PoC Design
`scripts/design_poc.py`

Per-finding PoC design. Searches repo for test/fixture/mock candidates, classifies finding severity, generates harness guidance, assertions, and run commands. Reads `preferred_toolchain` from `toolchain_config.json` written by cerberus-profiler.

**Outputs:** `poc_spec.md`, `severity_assessment.md`, `submission_notes.md`

### Test Scaffolding
`scripts/scaffold_tests.py`

Generates Foundry (default), Hardhat, or generic Solidity exploit and invariant test scaffolds. Injects audit context (privilege, invariant, rules, exploit families, proof plans, role constants, setters, sinks) as comments. Detects existing `test/Base.t.sol` and reuses it. Runs compile checks before reporting success.

**Outputs:** `<Contract>ExploitPoC.t.sol`, `<Contract>InvariantTest.t.sol`

### Submission Bundle
`scripts/build_submission_bundle.py`

Takes finding id, title, severity, template (minimal_with_poc / detailed_with_instructions / severity_argument_only), and PoC path. Copies PoC, writes report skeleton, updates `MANIFEST.md`.

**Outputs:** `.audit_board/PoC/final_submission/` bundle
