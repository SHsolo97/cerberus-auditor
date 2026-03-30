"""
cerberus_common — Shared Python foundation for all Cerberus audit skills.

Provides toolchain detection, file I/O, typed domain models, phase validation,
and an improvement hot-spot tracking loop.

Usage in skill scripts:
    from cerberus_common import PhaseStatus, finalize
    from cerberus_common.toolchain import resolve_toolchain, run_cmd, set_skill_root, which
    from cerberus_common.io import write_text, read_json, validate_phase_outputs
    from cerberus_common.improvement import append_improvement_entry, auto_log_status_observations

Each skill script MUST call set_skill_root(Path(__file__).resolve().parent.parent) once
before using any other cerberus_common functions.
"""
from __future__ import annotations

from . import io
from . import toolchain
from . import types
from . import improvement

from .types import (
    # Dataclasses
    CommandResult,
    PhaseStatus,
    ToolchainConfig,
    SemanticIndex,
    AuthorityGraph,
    AuthorityEdge,
    Sink,
    Setter,
    DependencyGraph,
    ExternalDependency,
    Action,
    StateTransition,
    FunctionEntry,
    ContractEntry,
    FileEntry,
    StateVar,
    MemberCall,
    SlotAssignment,
    InvariantCandidate,
    FindingCandidate,
    EvidenceItem,
    FindingConfirmation,
    ProofPlan,
    RepairEvent,
    RepairDecision,
    # Typed load helpers
    load_semantic_index,
    load_authority_graph,
    load_dependency_graph,
    load_action_catalog,
    load_state_transitions,
    load_invariant_candidates,
    load_finding_candidates,
    load_confirmations,
    load_proof_plans,
    load_repair_log,
    # Lazy path globals (initialized by toolchain.py:set_skill_root)
    IMPROVEMENT_LOG_FILE,
    IMPROVEMENT_SUMMARY_FILE,
    IMPROVEMENT_HOTSPOTS_FILE,
    RESOLVED_HOTSPOTS_FILE,
)

from .io import (
    finalize,
    write_text,
    read_text_file,
    read_json,
    write_status,
    emit_status,
    validate_phase_outputs,
    markdown_has_substantive_bullets,
    markdown_has_substantive_content,
    markdown_has_explicit_reason,
    strip_solidity_comments,
    file_has_concrete_contract,
    extract_contract_declarations,
    extract_imports,
    extract_inheritance,
    select_primary_contract,
    concat_imports,
    dedupe_flattened_solidity,
    utc_now_iso,
    make_failure_status,
    fatal_status,
    register_auto_log_fn,
    # Lazy-path globals
    AUDIT_DIR,
    STATUS_FILE,
    get_audit_dir,
    set_audit_dir,
    ensure_audit_dir,
    ensure_meta_dir,
)

from .toolchain import (
    set_skill_root,
    get_skill_root,
    resolve_toolchain,
    find_project_root,
    which,
    run_cmd,
    command_output,
    usable_slither_output,
    is_noise_only_slither_output,
    prepare_slither_build,
    get_slither_printers,
    choose_slither_printer,
    slither_command_candidates,
    detect_mode,
    dependency_map,
    safe_repo_relative_path,
    discover_solidity_files,
    repo_relative_path,
    file_exists_within,
    PROJECT_MARKERS,
    META_DIR,
    IMPROVEMENT_LOG_FILE,
    IMPROVEMENT_HOTSPOTS_FILE,
)

from .improvement import (
    append_improvement_entry,
    ensure_improvement_files,
    refresh_improvement_artifacts,
    auto_log_status_observations,
    resolve_hotspot,
    reopen_hotspot,
    read_resolved_hotspots,
    write_resolved_hotspots,
)

__all__ = [
    # io
    "finalize", "write_text", "read_text_file", "read_json", "write_status",
    "emit_status", "validate_phase_outputs", "markdown_has_substantive_bullets",
    "markdown_has_substantive_content", "markdown_has_explicit_reason",
    "strip_solidity_comments", "file_has_concrete_contract",
    "extract_contract_declarations", "extract_imports", "extract_inheritance",
    "select_primary_contract", "concat_imports", "dedupe_flattened_solidity",
    "utc_now_iso", "make_failure_status", "fatal_status", "register_auto_log_fn",
    # lazy-path globals (AUDIT_DIR triggers __getattr__ resolution at import time)
    "AUDIT_DIR", "STATUS_FILE", "get_audit_dir", "set_audit_dir",
    # toolchain
    "set_skill_root", "get_skill_root", "resolve_toolchain", "find_project_root",
    "which", "run_cmd", "command_output", "usable_slither_output",
    "is_noise_only_slither_output", "prepare_slither_build", "get_slither_printers",
    "choose_slither_printer", "slither_command_candidates", "detect_mode",
    "dependency_map", "safe_repo_relative_path", "discover_solidity_files",
    "repo_relative_path", "file_exists_within", "PROJECT_MARKERS",
    # types
    "CommandResult", "PhaseStatus", "ToolchainConfig", "SemanticIndex",
    "AuthorityGraph", "AuthorityEdge", "Sink", "Setter", "DependencyGraph",
    "ExternalDependency", "Action", "StateTransition", "FunctionEntry",
    "ContractEntry", "FileEntry", "StateVar", "MemberCall", "SlotAssignment",
    "InvariantCandidate", "FindingCandidate", "EvidenceItem",
    "FindingConfirmation", "ProofPlan", "RepairEvent", "RepairDecision",
    "load_semantic_index", "load_authority_graph", "load_dependency_graph",
    "load_action_catalog", "load_state_transitions", "load_invariant_candidates",
    "load_finding_candidates", "load_confirmations", "load_proof_plans",
    "load_repair_log",
    # improvement
    "append_improvement_entry", "ensure_improvement_files",
    "refresh_improvement_artifacts", "auto_log_status_observations",
    "resolve_hotspot", "reopen_hotspot", "read_resolved_hotspots",
    "write_resolved_hotspots",
]
