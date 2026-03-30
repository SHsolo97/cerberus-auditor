---
name: cerberus-profiler
description: Artifact extraction skill for cerberus-proof-auditor. Initializes the audit workspace, performs architecture analysis, extracts state vectors, and builds the semantic index. Produces flattened context, topology, privilege map, storage layout, and AST-backed semantic index. Use standalone to get a complete structural snapshot of a Solidity codebase before running cerberus-analyzer, cerberus-detective, or cerberus-scout.
---

# cerberus-profiler

**Invocable standalone:** YES. Run this skill independently to produce all extraction artifacts without invoking downstream phases.

**Prerequisites:** None beyond `target_contract_dir`.

**Outputs:** All artifacts are written to `.audit_board/` in the directory where the skill is invoked.

## Phases

### Phase 0 — Init Workspace
`resources/init_workspace.py`

Creates `.audit_board/` with 30+ placeholder artifacts, detects toolchains, generates a run_id, and creates `skill_monitor_context.json`. Non-destructive and rerunnable.

### Phase 0.5 — Preflight / Repair
`resources/preflight_or_repair.py`

Before any phase: validates scripts compile (py_compile), previous artifacts exist and are not stubs, applies two local syntax patches for known common bugs. Produces `repair_log.json`.

### Phase 1 — Architecture Analysis
`resources/analyze_architecture.py`

Discovers Solidity files, selects the primary contract, runs `forge flatten` (or falls back to `concat_imports()`), probes and runs Slither printers (contract-summary, modifiers, require). Falls back to source-derived topology. Parses README for trusted roles, invariants, known issues. Builds privilege map.

**Outputs:** `context_flattened.sol`, `topology_map.txt`, `contest_context.json`, `privilege_map.md`

### Phase 2 — State Vector Extraction
`resources/extract_state_vectors.py`

Scans for Slither state-surface printers (function-summary, entry-points, vars-and-auth), scans for `delegatecall` usage, runs `forge inspect <contract> storageLayout`, falls back to regex-based storage inference. Builds invariant map from address setters and role mutations.

**Outputs:** `external_calls.txt`, `storage_layout.json`, `invariant_map.md`

### Phase 2.5 — AST Semantic Index
`resources/ast_semantic_index.py`

Primary semantic indexer. Tries Slither `--json` first, parses JSON into typed schema with provenance (`_ast_mode: true`). Falls back to brace-depth regex indexer if AST is unavailable (sets `_ast_mode: false`). This is the preferred index for all downstream phases.

**Outputs:** `ast_semantic_index.json`

### Pre-AST — Semantic Index (Fallback)
`resources/build_semantic_index.py`

Pure regex-based semantic indexer using brace-depth function body extraction. Produces the same schema as the AST version. Used only when Slither JSON is unavailable.

**Outputs:** `semantic_index.json`

## Toolchain Support

Foundry (primary), Hardhat, Truffle, Brownie, Anchor, bare solc. Gracefully degrades when tools are unavailable.

## Reference Corpus

Owns the canonical `references/` directory (`validations.md`, `sharp_edges.md`, `patterns.md`). Other skills reference it via `../../profiler/references/` or `CERBERUS_REFS_DIR`.
