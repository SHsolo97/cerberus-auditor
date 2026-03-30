---
name: cerberus-detective
description: Contradiction-finding engine for cerberus-proof-auditor. Reads all graph artifacts from cerberus-analyzer and produces finding candidates across six exploit families, confirms them against scope and guard-surface analysis, and triages them into exploit hypotheses with proof maturity status. Use standalone after cerberus-profiler and cerberus-analyzer have completed.
---

# cerberus-detective

**Invocable standalone:** YES. Requires the full artifact set from cerberus-profiler and cerberus-analyzer in `.audit_board/`.

**Inputs:** `authority_graph.json`, `dependency_graph.json`, `action_catalog.json`, `invariant_candidates.json`, `rule_scan.json`, `ast_semantic_index.json`, `contest_context.json`

## Phases

### Finding Candidates
`scripts/generate_finding_candidates.py`

The core contradiction-finding engine. Six finding families:

1. **authority_drift** — Guard-surface mismatches between setters and sinks on shared state
2. **callback_state_drift** — External calls followed by writes without guard protection
3. **broken_recovery** — Recovery/settle/close functions without guards
4. **implementation_rebinding** — Setter sequences that rebind contract-typed state slots
5. **dependency_recovery_lockup** — Settlement-critical dependencies without rotation paths
6. **settlement_dependency_drift** — Settlement-critical dependencies used in settlement reads without verification

Maintains `dominated_*` sets to prevent duplicates. Produces `finding_candidates.json` sorted by confidence score.

**Outputs:** `finding_candidates.json`

### Finding Confirmation
`scripts/confirm_findings.py`

Structured confirmation: dead-code rejection (interface-only sinks), scope disqualification, parent-guard-shadow detection, guard equivalence check. Confidence boost/deduction based on scope and guard analysis.

**Outputs:** `finding_confirmations.json`

### Hypothesis Triage
`scripts/triage_hypotheses.py`

Fuses finding candidates, confirmations, and proof plans into exploit hypotheses with five-stage proof maturity: `hypothesis` → `source_confirmed` → `locally_reproduced` → `deterministic_poc` → `submission_ready`. A sixth state, `rejected`, applies when false-positive paths explicitly rule out a finding.

**Outputs:** `exploit_hypotheses.md`, `proof_status.json`
