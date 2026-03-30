---
name: cerberus-common
description: Shared Python foundation for Cerberus audit skills. Provides toolchain detection, file I/O, typed domain models, phase validation, and the improvement hot-spot loop. Imported by all cerberus-profiler, cerberus-analyzer, cerberus-detective, and cerberus-scout skills. Not independently invocable.
---

# cerberus-common

**Not independently invocable.** Import this package from skill scripts.

## What it provides

- **Toolchain detection** — `resolve_toolchain()` detects Foundry, Hardhat, Truffle, Brownie, Anchor, and bare solc projects. Records all detected toolchains and resolves binaries from 100+ fallback paths.
- **Command execution** — `run_cmd()` wraps subprocess with 120s timeout and returns structured `CommandResult`.
- **Atomic file I/O** — `write_text()` uses temp-file + rename + fsync for crash-safe writes. `read_json()` and `read_text_file()` handle errors gracefully.
- **Typed domain model** — All audit artifacts have dataclass representations: `SemanticIndex`, `AuthorityGraph`, `Sink`, `Setter`, `Action`, `FindingCandidate`, `FindingConfirmation`, `ProofPlan`, etc.
- **Typed load helpers** — `load_semantic_index()`, `load_authority_graph()`, `load_finding_candidates()`, etc. load JSON artifacts into typed Python objects.
- **Phase validation** — `validate_phase_outputs()` enforces structural constraints on every phase's output artifacts. Phases with missing stubs or invalid JSON are marked `degraded`.
- **Improvement loop** — `append_improvement_entry()` atomically appends to a shared JSONL log. `auto_log_status_observations()` is called automatically by `finalize()`. `refresh_improvement_artifacts()` aggregates the log into `improvement_hotspots.json` and `skill_improvements.md`.

## Startup contract

Every skill script MUST call `set_skill_root()` once before using any other cerberus_common functions:

```python
from pathlib import Path
from cerberus_common.toolchain import set_skill_root
set_skill_root(Path(__file__).resolve().parent.parent)  # resources/ -> skill root
```

This binds all path-dependent constants (`AUDIT_DIR`, `META_DIR`, `IMPROVEMENT_LOG_FILE`, etc.) to the correct directory.

## Module overview

| Module | Responsibility |
|--------|---------------|
| `cerberus_common.types` | All dataclasses, enums, and typed `load_*` helpers |
| `cerberus_common.io` | File I/O, status management, markdown helpers, `finalize()`, `validate_phase_outputs()` |
| `cerberus_common.toolchain` | Binary resolution, `run_cmd()`, Slither integration, `resolve_toolchain()`, `set_skill_root()` |
| `cerberus_common.improvement` | Improvement hot-spot loop, `auto_log_status_observations()` |

## Artifact layout convention

All skills write to `.audit_board/` (a path relative to wherever the skill is invoked). Skills read pre-existing artifacts from `.audit_board/` and write their own outputs there. The shared blackboard model means any skill can depend on any prior skill's outputs without coordination.
