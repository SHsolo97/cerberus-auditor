"""
resources/common.py — Thin shim that re-exports cerberus_common.

Must be imported before any other cerberus_common symbols.
Sets SKILL_ROOT so all path-dependent constants resolve correctly.
"""
from __future__ import annotations

import sys
from pathlib import Path

# Resolve SKILL_ROOT: resources/common.py -> <skill>/ -> cerberus-proof-auditor/
SKILL_ROOT = Path(__file__).resolve().parent.parent

# Insert cerberus_common onto sys.path so this skill can import it.
# The package root is: cerberus-proof-auditor/cerberus-common/cerberus_common/
# SKILL_ROOT (e.g. /path/to/profiler/) is two levels above resources/.
CERBERUS_COMMON_PKG = SKILL_ROOT.parent / "cerberus-common"  # add this dir so 'cerberus_common' is findable
if str(CERBERUS_COMMON_PKG) not in sys.path:
    sys.path.insert(0, str(CERBERUS_COMMON_PKG))

# Initialize SKILL_ROOT in cerberus_common before any other imports.
# The skill root (profiler/, analyzer/, etc.) is SKILL_ROOT; the meta/improvement loop
# lives at the cerberus-proof-auditor level = SKILL_ROOT.parent.
from cerberus_common.toolchain import set_skill_root
set_skill_root(SKILL_ROOT.parent)  # cerberus-proof-auditor/ — where meta/ lives

# Re-export everything from cerberus_common for backward compatibility
from cerberus_common import (
    # PhaseStatus and finalize
    PhaseStatus, finalize,
    # IO
    write_text, read_text_file, read_json, write_status, emit_status,
    validate_phase_outputs,
    markdown_has_substantive_bullets, markdown_has_substantive_content,
    markdown_has_explicit_reason, strip_solidity_comments,
    file_has_concrete_contract,
    extract_contract_declarations, extract_imports, extract_inheritance,
    select_primary_contract, concat_imports, dedupe_flattened_solidity,
    utc_now_iso, make_failure_status, fatal_status,
    ensure_audit_dir, ensure_meta_dir,
    # Lazy-path globals (triggers __getattr__ resolution in cerberus_common.io)
    AUDIT_DIR, STATUS_FILE, get_audit_dir, set_audit_dir,
    # Toolchain
    set_skill_root, get_skill_root, resolve_toolchain, find_project_root,
    which, run_cmd, command_output,
    usable_slither_output, is_noise_only_slither_output,
    prepare_slither_build, get_slither_printers, choose_slither_printer,
    slither_command_candidates, detect_mode, dependency_map,
    safe_repo_relative_path, discover_solidity_files, repo_relative_path,
    file_exists_within, PROJECT_MARKERS,
    META_DIR, IMPROVEMENT_LOG_FILE, IMPROVEMENT_SUMMARY_FILE, IMPROVEMENT_HOTSPOTS_FILE,
    # Domain types
    CommandResult, ToolchainConfig,
    SemanticIndex, AuthorityGraph, AuthorityEdge, Sink, Setter,
    DependencyGraph, ExternalDependency,
    Action, StateTransition, FunctionEntry, ContractEntry, FileEntry,
    StateVar, MemberCall, SlotAssignment,
    InvariantCandidate, FindingCandidate, EvidenceItem,
    FindingConfirmation, ProofPlan, RepairEvent, RepairDecision,
    # Typed load helpers
    load_semantic_index, load_authority_graph, load_dependency_graph,
    load_action_catalog, load_state_transitions, load_invariant_candidates,
    load_finding_candidates, load_confirmations, load_proof_plans, load_repair_log,
    # Improvement
    append_improvement_entry, ensure_improvement_files,
    refresh_improvement_artifacts, auto_log_status_observations,
    resolve_hotspot, reopen_hotspot, read_resolved_hotspots, write_resolved_hotspots,
)
