---
name: cerberus-analyzer
description: Graph analysis and rule-scan skill for cerberus-proof-auditor. Reads the semantic index from cerberus-profiler and produces the action catalog, authority graph, dependency graph, invariant candidates, and rule-scan exploit-family rankings. Use standalone after cerberus-profiler has produced the semantic index.
---

# cerberus-analyzer

**Invocable standalone:** YES. Requires `ast_semantic_index.json` (or `semantic_index.json`) in `.audit_board/` from cerberus-profiler.

**Inputs:** `ast_semantic_index.json`, `context_flattened.sol` (optional), `.audit_board/` state from cerberus-profiler.

## Phases

### Action Catalog
`resources/extract_actions.py`

Loads the semantic index, builds inheritance-aware resolved function maps, transitively resolves effects through internal calls and member calls. Produces `action_catalog.json` and `state_transition_map.json`.

**Outputs:** `action_catalog.json`, `state_transition_map.json`

### Authority Graph
`resources/build_authority_graph.py`

Loads the semantic index, builds authority graph with roles, guard→function edges, sinks, and setters. Uses transitive guard analysis.

**Outputs:** `authority_graph.json`

### Dependency Graph
`resources/build_dependency_graph.py`

Regex-scans for oracle/registry/bridge/proxy/callback dependency patterns, propagates through inheritance, classifies criticality (settlement_critical, recovery_critical, gating).

**Outputs:** `dependency_graph.json`

### Invariant Mining
`resources/mine_invariants.py`

Reads action catalog, authority graph, dependency graph. Heuristically generates invariant candidates: recovery paths, authority rotation, oracle safety, trust boundary patterns, unguarded sinks/setters.

**Outputs:** `invariant_candidates.json`

### Rule Scan
`resources/rule_scan.py`

Parses `references/validations.md` and `references/sharp_edges.md` (from cerberus-profiler at `../../profiler/references/`), scans Solidity files with regex, scores exploit families. Suppresses known noise categories.

**Outputs:** `rule_scan.json`, `rule_scan.md`, `exploit_rankings.md`

## Outputs

All artifacts written to `.audit_board/`:
- `action_catalog.json`
- `state_transition_map.json`
- `authority_graph.json`
- `dependency_graph.json`
- `invariant_candidates.json`
- `rule_scan.json`, `rule_scan.md`, `exploit_rankings.md`
