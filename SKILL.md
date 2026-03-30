---
name: cerberus-proof-auditor
description: Exploit-driven smart-contract audit skill for any Solidity codebase. Runs four sub-skills in sequence: profiler (artifact extraction), analyzer (graph + rule scan), detective (contradiction finding), and scout (proof planning + submission). Works with Foundry, Hardhat, Truffle, Brownie, Anchor, and bare solc.
---

# Cerberus Proof Auditor

**Invocable standalone:** YES. Run with `--target-dir <path>` to start the full pipeline.

**Prerequisites:** None beyond `--target-dir` pointing to a Solidity source directory.

---

## Sub-Skills

Each sub-skill is independently invocable. The full pipeline runs all four:

| # | Skill | Invocable standalone | Core output |
|---|---|---|---|
| 1 | **`profiler/`** | YES | `ast_semantic_index.json`, `context_flattened.sol`, `storage_layout.json`, `privilege_map.md` |
| 2 | **`analyzer/`** | YES (needs profiler output) | `authority_graph.json`, `dependency_graph.json`, `action_catalog.json`, `rule_scan.json` |
| 3 | **`detective/`** | YES (needs profiler + analyzer output) | `finding_candidates.json`, `finding_confirmations.json`, `exploit_hypotheses.md` |
| 4 | **`scout/`** | YES (needs detective output) | `proof_plans.json`, `poc_spec.md`, scaffold tests, submission bundle |

All artifacts live in `.audit_board/` relative to the invocation directory.

---

## Pipeline Order

```
init → preflight_or_repair → architecture → state_vectors
    → semantic_index → action_catalog → authority_graph
    → dependency_graph → rule_scan → invariant_candidates
    → finding_candidates → finding_confirmation
    → proof_planning → hypothesis_triage → poc_design
    → scaffold_tests → submission_bundle
```

Each phase writes its status to `.audit_board/status.json`. Run phases sequentially; before starting a later phase, confirm prior phases produced usable artifacts. If a phase has `ok: false` only because tooling degraded, inspect the artifacts and warnings and continue only if the output is materially useful.

When both `semantic_index.json` and `ast_semantic_index.json` are present, downstream phases MUST prefer the AST-backed version.

---

## Operating Rules

**Artifact quality over file creation.** Empty heading stubs and placeholder-only markdown are failures. Write "Not determined — [reason]" rather than TODO when information is unavailable.

**In-scope only.** Never overwrite files outside `.audit_board/` or `test/`.

**Graceful degradation.** When Foundry is absent, phases fall back to toolchain-agnostic alternatives: import-graph concatenation for flattening, regex-based state extraction for storage layout, generic Solidity templates for test scaffolding.

**Proof maturity tracking.** Each finding progresses through: `hypothesis` → `source_confirmed` → `locally_reproduced` → `deterministic_poc` → `submission_ready`. A sixth state, `rejected`, applies when guard equivalence, parent-guard shadow, out-of-scope disqualification, or dead-code filtering explicitly rules out a finding candidate.

**Findings are hypotheses until confirmed.** Treat generated artifacts as tentative until validated by source review or deterministic tests.

**Reference corpus.** Use `references/sharp_edges.md` to pressure-test attack hypotheses. Use `references/validations.md` to sanity-check whether suspicious code patterns deserve explicit mention. Use `references/patterns.md` only when proposing mitigations or test ideas.

**Existing harnesses first.** Prefer reusing `test/Base.t.sol` or similar repo harnesses when scaffolding proofs. Record the exact file path in `poc_spec.md`.

**Separation per subject.** Never merge multiple contracts or vulnerability classes into a single analysis entry. Each attack vector is a separate numbered entry.

---

## Usage

### Full pipeline (all four sub-skills)

```bash
skill cerberus-proof-auditor --target-dir src
```

### Standalone sub-skills

```bash
# Step 1: Extract artifacts
skill cerberus-profiler --target-dir src

# Step 2: Build graphs
skill cerberus-analyzer --target-dir src

# Step 3: Find contradictions
skill cerberus-detective --target-dir src

# Step 4: Plan proofs
skill cerberus-scout --target-dir src
```

---

## Skill 1: `profiler/` — Artifact Extraction

**Invocable standalone:** YES. Run `skill cerberus-profiler --target-dir <path>` to produce all extraction artifacts without downstream phases.

Owns the canonical `references/` corpus. Other skills reference it via `../../profiler/references/`.

### Phase 0 — Init Workspace
`resources/init_workspace.py --target-dir <dir>`

Creates `.audit_board/` with 30+ placeholder artifacts, detects toolchains, generates a run_id, and creates `skill_monitor_context.json`. Non-destructive and rerunnable.

### Phase 0.5 — Preflight / Repair
`resources/preflight_or_repair.py --phase-name <name> --script-path <path> --target-dir <dir>`

Before any phase: validates scripts compile (`py_compile`), previous artifacts exist and are not stubs, applies two local syntax patches for known common bugs. Produces `repair_log.json`.

### Phase 1 — Architecture Analysis
`resources/analyze_architecture.py --target-dir <dir>`

Discovers Solidity files, selects the primary contract, runs `forge flatten` (or falls back to `concat_imports()`), probes and runs Slither printers (contract-summary, modifiers, require). Falls back to source-derived topology. Parses README for trusted roles, invariants, known issues. Builds privilege map.

**Outputs:** `context_flattened.sol`, `topology_map.txt`, `contest_context.json`, `privilege_map.md`

### Phase 2 — State Vector Extraction
`resources/extract_state_vectors.py --target-dir <dir>`

Scans for Slither state-surface printers (function-summary, entry-points, vars-and-auth), scans for `delegatecall` usage, runs `forge inspect <contract> storageLayout`, falls back to regex-based storage inference. Builds invariant map from address setters and role mutations.

**Outputs:** `external_calls.txt`, `storage_layout.json`, `invariant_map.md`

### Phase 2.5 — AST Semantic Index
`resources/ast_semantic_index.py --target-dir <dir>`

Primary semantic indexer. Tries Slither `--json` first, parses JSON into typed schema with provenance (`_ast_mode: true`). Falls back to brace-depth regex indexer if AST is unavailable (sets `_ast_mode: false`).

**Outputs:** `ast_semantic_index.json`

### Pre-AST Fallback
`resources/build_semantic_index.py --target-dir <dir>`

Pure regex-based semantic indexer. Used only when Slither JSON is unavailable. Produces `semantic_index.json`.

---

## Skill 2: `analyzer/` — Graph Analysis + Rule Scan

**Invocable standalone:** YES. Run `skill cerberus-analyzer --target-dir <path>` after `cerberus-profiler` has produced `ast_semantic_index.json`.

### Action Catalog
`resources/extract_actions.py`

Loads the semantic index, builds inheritance-aware resolved function maps, transitively resolves effects through internal calls and member calls. Produces `action_catalog.json` and `state_transition_map.json`.

### Authority Graph
`resources/build_authority_graph.py`

Builds authority graph with roles, guard→function edges, sinks, and setters. Uses transitive guard analysis.

### Dependency Graph
`resources/build_dependency_graph.py`

Regex-scans for oracle/registry/bridge/proxy/callback dependency patterns, propagates through inheritance, classifies criticality (settlement_critical, recovery_critical, gating).

### Invariant Mining
`resources/mine_invariants.py`

Reads action catalog, authority graph, dependency graph. Heuristically generates invariant candidates: recovery paths, authority rotation, oracle safety, trust boundary patterns, unguarded sinks/setters.

### Rule Scan
`resources/rule_scan.py`

Parses `references/validations.md` and `references/sharp_edges.md`, scans Solidity files with regex, scores exploit families. Suppresses known noise categories.

**Outputs:** `rule_scan.json`, `rule_scan.md`, `exploit_rankings.md`

---

## Skill 3: `detective/` — Contradiction-Finding Engine

**Invocable standalone:** YES. Run `skill cerberus-detective --target-dir <path>` after `cerberus-profiler` and `cerberus-analyzer` have completed.

### Finding Candidates
`resources/generate_finding_candidates.py`

Six finding families:

1. **authority_drift** — Guard-surface mismatches between setters and sinks on shared state
2. **callback_state_drift** — External calls followed by writes without guard protection
3. **broken_recovery** — Recovery/settle/close functions without guards
4. **implementation_rebinding** — Setter sequences that rebind contract-typed state slots
5. **dependency_recovery_lockup** — Settlement-critical dependencies without rotation paths
6. **settlement_dependency_drift** — Settlement-critical dependencies used in settlement reads without verification

Maintains `dominated_*` sets to prevent duplicates. Produces `finding_candidates.json` sorted by confidence score.

### Finding Confirmation
`resources/confirm_findings.py`

Structured confirmation: dead-code rejection (interface-only sinks), scope disqualification, parent-guard-shadow detection, guard equivalence check. Confidence boost/deduction based on scope and guard analysis.

### Hypothesis Triage
`resources/triage_hypotheses.py`

Fuses finding candidates, confirmations, and proof plans into exploit hypotheses with five-stage proof maturity: `hypothesis` → `source_confirmed` → `locally_reproduced` → `deterministic_poc` → `submission_ready`. A sixth state, `rejected`, applies when false-positive paths explicitly rule out a finding.

**Outputs:** `exploit_hypotheses.md`, `proof_status.json`

---

## Skill 4: `scout/` — Proof Planning + Submission

**Invocable standalone:** YES. Run `skill cerberus-scout --target-dir <path>` after `cerberus-detective` has produced `finding_confirmations.json`.

### Proof Planning
`resources/plan_proofs.py`

Generates structured proof plans from confirmed findings. Classifies confirmability:
- `confirmable_and_reproducible` — strong source signal, low false-positive risk
- `confirmable_but_weak` — useful signal but significant unknowns
- `interesting_but_unconfirmed` — requires more investigation

Produces harness candidates, transaction sequences, assertions, expected outcomes, and minimum test commands per toolchain (Foundry, Hardhat, Truffle, Brownie, Anchor, bare).

### PoC Design
`resources/design_poc.py`

Per-finding PoC design. Searches repo for test/fixture/mock candidates, classifies finding severity, generates harness guidance, assertions, and run commands. Reads `preferred_toolchain` from `toolchain_config.json` written by profiler.

**Outputs:** `poc_spec.md`, `severity_assessment.md`, `submission_notes.md`

### Test Scaffolding
`resources/scaffold_tests.py`

Generates Foundry (default), Hardhat, or generic Solidity exploit and invariant test scaffolds. Injects audit context (privilege, invariant, rules, exploit families, proof plans, role constants, setters, sinks, violated_invariant, blocking_assumptions) as comments. Detects existing `test/Base.t.sol` and reuses it. Runs compile checks before reporting success.

### Submission Bundle
`resources/build_submission_bundle.py`

Takes finding id, title, severity, template (minimal_with_poc / detailed_with_instructions / severity_argument_only), and PoC path. Copies PoC, writes report skeleton, updates `MANIFEST.md`.

**Outputs:** `.audit_board/PoC/final_submission/` bundle

---

## Blackbird Layout

All artifacts live under `.audit_board/` relative to the invocation directory.

**Profiler artifacts:** `context_flattened.sol`, `topology_map.txt`, `contest_context.json`, `privilege_map.md`, `external_calls.txt`, `storage_layout.json`, `invariant_map.md`, `semantic_index.json`, `ast_semantic_index.json`

**Analyzer artifacts:** `action_catalog.json`, `state_transition_map.json`, `authority_graph.json`, `dependency_graph.json`, `invariant_candidates.json`, `rule_scan.json`, `rule_scan.md`, `exploit_rankings.md`

**Detective artifacts:** `finding_candidates.json`, `finding_confirmations.json`, `exploit_hypotheses.md`, `proof_status.json`

**Scout artifacts:** `proof_plans.json`, `poc_spec.md`, `severity_assessment.md`, `submission_notes.md`, `test/root-audit/*.t.sol`, `.audit_board/PoC/final_submission/`

**Status:** `.audit_board/status.json`

---

## Improvement Loop

The improvement loop lives in `cerberus-common/`. Every phase calls `auto_log_status_observations()`. Log observations with:

```bash
python3 cerberus-common/cerberus_common/scripts/log_improvement.py \
  --run-id <run_id> --phase <phase_name> --severity medium \
  --category output_quality \
  --summary "<what was observed>" \
  --suggested-fix "<concrete fix>"
```

Resolve hotspots:
```bash
python3 cerberus-common/cerberus_common/scripts/resolve_hotspot.py \
  --action resolve --fingerprint <id> --resolution-note "<what changed>"
```

Persistent state:
- `meta/skill_improvements.jsonl`
- `meta/skill_improvements.md`
- `meta/improvement_hotspots.json`
- `meta/resolved_hotspots.json`

Read `meta/improvement_hotspots.json` before each run; treat the top 3 recurring hotspots as a preflight checklist. When a hotspot is fixed, resolve it. If the same issue reappears, reopen it.

---

## Proof Maturity Labels

| Label | Meaning |
|---|---|
| `hypothesis` | Structural signal detected; not yet reviewed in source |
| `source_confirmed` | Guard drift or authority gap confirmed in source code |
| `locally_reproduced` | Deterministic test demonstrates the vulnerability |
| `deterministic_poc` | PoC is stable and auditable |
| `submission_ready` | Report written and peer-reviewed |
| `rejected` | Explicit false-positive rejection path fired |

## Proof Confirmability Labels

Each proof plan MUST include a `confirmability` field:

| Label | Criteria |
|---|---|
| `confirmable_and_reproducible` | `source_confirmed` status, confidence ≥ 0.75, no disqualifiers, concrete transaction sequence |
| `confirmable_but_weak` | `source_confirmed` with confidence ≥ 0.5, but no concrete reproduction path |
| `interesting_but_unconfirmed` | `weak_signal` or `rejected` — document with a "what would it take" note |

Each proof plan also MUST include:
- `false_positive_risk`: `low | medium | high | unknown`
- `blocking_assumptions`: explicit list of preconditions that must hold for the PoC to work
- `minimum_test_commands`: concrete test commands per detected toolchain

## Finding Confirmation Schema

Each entry in `finding_confirmations.json` MUST include:

| Field | Type | Description |
|---|---|---|
| `candidate_id` | string | Finding ID from `finding_candidates.json` |
| `status` | string | `source_confirmed \| weak_signal \| rejected` |
| `rejection_reason` | string \| null | Explicit reason if `rejected`; null otherwise |
| `scope_status` | string | `in_scope \| out_of_scope \| unknown` |
| `confidence_score` | float | Adjusted score in [0.0, 1.0] |
| `confidence_boost` | float | Delta applied to base confidence |
| `guard_analysis` | string | Human-readable guard-surface analysis |
| `disqualifiers` | string[] | Blocking unknowns or scope issues |

---

## Regression Tests

Run the full benchmark suite:

```bash
python3 meta/bench_eval.py
```

Run individual regression checks:

```bash
python3 meta/eval_regressions.py
```

Benchmarks are in `benchmarks/` (73 fixture directories). Each fixture includes Solidity source, `foundry.toml`, and an `expected.json` that encodes expected findings, confirmations, proof plans, preflight decisions, and corruption/recovery behaviors.

Regression targets include: authority graph must have ≥1 sink and ≥1 setter; dependency graph must have ≥1 dependency; finding candidates must include expected IDs; confirmations must reflect expected maturity.

---

## Severity Coaching

- **High:** Direct fund loss, permanent lockup, or irrecoverable liveness failure over protocol-owned assets.
- **Medium:** Concrete but bounded asset or trust-boundary failures.
- **Low:** Governance/recovery weaknesses that do not directly freeze or steal assets.
- **Note amplifiers explicitly** in `submission_notes.md` rather than overselling impact.
