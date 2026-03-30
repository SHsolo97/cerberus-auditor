"""
cerberus_common.types — Domain model for all Cerberus skills.

All dataclass definitions, enums, and typed load helpers.
No imports from other cerberus_common submodules.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

# ── Shared path constants ───────────────────────────────────────────────────────
# Set by toolchain.py before io.py or improvement.py are used.
SKILL_ROOT: Optional[Path] = None
AUDIT_DIR = Path(".audit_board")
STATUS_FILE = AUDIT_DIR / "status.json"
REPO_MARKERS = ("foundry.toml", ".git")
META_DIR = SKILL_DIR = None  # type: ignore[assignment] — set by toolchain.py
IMPROVEMENT_LOG_FILE = None  # type: ignore[assignment]
IMPROVEMENT_SUMMARY_FILE = None  # type: ignore[assignment]
IMPROVEMENT_HOTSPOTS_FILE = None  # type: ignore[assignment]
RESOLVED_HOTSPOTS_FILE = None  # type: ignore[assignment]


def _ensure_paths(root: Path) -> None:
    """Called by toolchain.py to bind SKILL_ROOT-dependent paths."""
    global SKILL_ROOT, META_DIR, SKILL_DIR, IMPROVEMENT_LOG_FILE
    global IMPROVEMENT_SUMMARY_FILE, IMPROVEMENT_HOTSPOTS_FILE, RESOLVED_HOTSPOTS_FILE
    SKILL_ROOT = root
    META_DIR = SKILL_DIR = root / "meta"
    IMPROVEMENT_LOG_FILE = META_DIR / "skill_improvements.jsonl"
    IMPROVEMENT_SUMMARY_FILE = META_DIR / "skill_improvements.md"
    IMPROVEMENT_HOTSPOTS_FILE = META_DIR / "improvement_hotspots.json"
    RESOLVED_HOTSPOTS_FILE = META_DIR / "resolved_hotspots.json"


# ── Toolchain config ──────────────────────────────────────────────────────────

PROJECT_MARKERS: Dict[str, Tuple[str, ...]] = {
    "foundry": ("foundry.toml",),
    "hardhat": ("hardhat.config.js", "hardhat.config.ts"),
    "truffle": ("truffle-config.js",),
    "brownie": ("brownie-config.yaml",),
    "anchor": ("Anchor.toml",),
}
_UNIVERSAL_MARKERS: Tuple[str, ...] = (".git",)


@dataclass
class ToolchainConfig:
    project_root: Path
    detected_toolchains: List[str] = field(default_factory=list)
    binaries: Dict[str, Optional[str]] = field(default_factory=dict)
    preferred_toolchain: str = "unknown"
    flatten_available: bool = False
    storage_layout_available: bool = False
    test_scaffold_family: str = "generic"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "detected_toolchains": self.detected_toolchains,
            "preferred_toolchain": self.preferred_toolchain,
            "flatten_available": self.flatten_available,
            "storage_layout_available": self.storage_layout_available,
            "test_scaffold_family": self.test_scaffold_family,
            "binaries": {k: v for k, v in self.binaries.items() if v},
        }


# ── Command result ────────────────────────────────────────────────────────────

@dataclass
class CommandResult:
    command: List[str]
    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return self.returncode == 0 and not self.timed_out


# ── Phase status ──────────────────────────────────────────────────────────────

@dataclass
class PhaseStatus:
    phase: str
    ok: bool
    mode: str
    artifacts: Dict[str, str]
    warnings: List[str]
    errors: List[str]
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── Repair decision ───────────────────────────────────────────────────────────

class RepairDecision(str, Enum):
    RESUME = "resume"
    STOP_AND_ESCALATE = "stop_and_escalate"
    STOP_AND_FIX = "stop_and_fix"
    PATCH_BEFORE_RESUME = "patch_before_resume"
    SKIP_PHASE = "skip_phase"


# ── Repair event ───────────────────────────────────────────────────────────────

@dataclass
class RepairEvent:
    phase: str
    script: str
    decision: str
    failure_kind: Optional[str]
    evidence: List[str]
    timestamp: str
    patch_applied: bool
    patch_content: Optional[str]
    retry_count: int
    root_cause: Optional[str]

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Dict[str, object]) -> "RepairEvent":
        return cls(
            phase=str(d.get("phase", "")),
            script=str(d.get("script", "")),
            decision=str(d.get("decision", "resume")),
            failure_kind=str(d["failure_kind"]) if d.get("failure_kind") else None,
            evidence=list(d.get("evidence", [])),
            timestamp=str(d.get("timestamp", "")),
            patch_applied=bool(d.get("patch_applied", False)),
            patch_content=str(d["patch_content"]) if d.get("patch_content") else None,
            retry_count=int(d.get("retry_count", 0)),
            root_cause=str(d["root_cause"]) if d.get("root_cause") else None,
        )


# ── Semantic index domain ─────────────────────────────────────────────────────

@dataclass
class StateVar:
    type: str
    name: str
    contract: str


@dataclass
class MemberCall:
    receiver: str
    receiver_type: str
    bound_types: List[str]
    function: str


@dataclass
class SlotAssignment:
    target: str
    source: str


@dataclass
class FunctionEntry:
    contract: str
    name: str
    params: str
    visibility: str
    modifiers: List[str]
    auth_guards: List[str]
    writes: List[str]
    true_writes: List[str]
    false_writes: List[str]
    state_reads: List[str]
    external_calls: List[str]
    internal_calls: List[str]
    member_calls: List[MemberCall]
    slot_assignments: List[SlotAssignment]
    require_guards: List[str]
    role_constants: List[str]
    sink_hints: List[str]
    state_keywords: List[str]
    line_start: int
    line_end: int

    @classmethod
    def from_dict(cls, d: Dict[str, object]) -> "FunctionEntry":
        return cls(
            contract=str(d.get("contract", "")),
            name=str(d.get("name", "")),
            params=str(d.get("params", "")),
            visibility=str(d.get("visibility", "internal")),
            modifiers=list(d.get("modifiers", [])),
            auth_guards=list(d.get("auth_guards", [])),
            writes=list(d.get("writes", [])),
            true_writes=list(d.get("true_writes", [])),
            false_writes=list(d.get("false_writes", [])),
            state_reads=list(d.get("state_reads", [])),
            external_calls=list(d.get("external_calls", [])),
            internal_calls=list(d.get("internal_calls", [])),
            member_calls=[MemberCall(**m) if isinstance(m, dict) else m for m in d.get("member_calls", [])],
            slot_assignments=[SlotAssignment(**s) if isinstance(s, dict) else s for s in d.get("slot_assignments", [])],
            require_guards=list(d.get("require_guards", [])),
            role_constants=list(d.get("role_constants", [])),
            sink_hints=list(d.get("sink_hints", [])),
            state_keywords=list(d.get("state_keywords", [])),
            line_start=int(d.get("line_start", 0)),
            line_end=int(d.get("line_end", 0)),
        )


@dataclass
class ContractEntry:
    path: str
    name: str
    kind: str  # "contract" | "interface" | "library"
    inherits: List[str]
    role_constants: List[str]

    @classmethod
    def from_dict(cls, d: Dict[str, object]) -> "ContractEntry":
        return cls(
            path=str(d.get("path", "")),
            name=str(d.get("name", "")),
            kind=str(d.get("kind", "contract")),
            inherits=list(d.get("inherits", [])),
            role_constants=list(d.get("role_constants", [])),
        )


@dataclass
class FileEntry:
    path: str
    contracts: List[ContractEntry]
    functions: List[FunctionEntry]
    state_vars: List[StateVar]
    state_bindings: Dict[str, List[str]]
    role_constants: List[str]

    @classmethod
    def from_dict(cls, d: Dict[str, object]) -> "FileEntry":
        return cls(
            path=str(d.get("path", "")),
            contracts=[ContractEntry.from_dict(c) if isinstance(c, dict) else c for c in d.get("contracts", [])],
            functions=[FunctionEntry.from_dict(f) if isinstance(f, dict) else f for f in d.get("functions", [])],
            state_vars=[StateVar(**sv) if isinstance(sv, dict) else sv for sv in d.get("state_vars", [])],
            state_bindings=dict(d.get("state_bindings", {})),
            role_constants=list(d.get("role_constants", [])),
        )


@dataclass
class SemanticIndex:
    _ast_mode: bool
    _ast_source: Optional[str]  # "slither-json" | "regex-fallback" | None
    mode: str  # "full" | "degraded" | "placeholder"
    files: List[FileEntry]
    contracts: List[ContractEntry]

    @classmethod
    def from_dict(cls, d: Dict[str, object]) -> "SemanticIndex":
        return cls(
            _ast_mode=bool(d.get("_ast_mode", False)),
            _ast_source=str(d["_ast_source"]) if d.get("_ast_source") else None,
            mode=str(d.get("mode", "placeholder")),
            files=[FileEntry.from_dict(f) if isinstance(f, dict) else f for f in d.get("files", [])],
            contracts=[ContractEntry.from_dict(c) if isinstance(c, dict) else c for c in d.get("contracts", [])],
        )


# ── Authority graph domain ─────────────────────────────────────────────────────

@dataclass
class AuthorityEdge:
    path: str
    guard: str
    function: str
    kind: str  # "direct_guard" | "require_guard"


@dataclass
class Sink:
    contract: str
    function: str
    visibility: str
    guards: List[str]
    require_guards: List[str]
    auth_guards: List[str]
    sink_hints: List[str]
    writes: List[str]
    external_calls: List[str]
    line_start: Optional[int]

    @classmethod
    def from_dict(cls, d: Dict[str, object]) -> "Sink":
        return cls(
            contract=str(d.get("contract", "")),
            function=str(d.get("function", "")),
            visibility=str(d.get("visibility", "")),
            guards=list(d.get("guards", [])),
            require_guards=list(d.get("require_guards", [])),
            auth_guards=list(d.get("auth_guards", [])),
            sink_hints=list(d.get("sink_hints", [])),
            writes=list(d.get("writes", [])),
            external_calls=list(d.get("external_calls", [])),
            line_start=int(d["line_start"]) if d.get("line_start") else None,
        )


@dataclass
class Setter:
    contract: str
    function: str
    visibility: str
    guards: List[str]
    writes: List[str]
    line_start: Optional[int]

    @classmethod
    def from_dict(cls, d: Dict[str, object]) -> "Setter":
        return cls(
            contract=str(d.get("contract", "")),
            function=str(d.get("function", "")),
            visibility=str(d.get("visibility", "")),
            guards=list(d.get("guards", [])),
            writes=list(d.get("writes", [])),
            line_start=int(d["line_start"]) if d.get("line_start") else None,
        )


@dataclass
class AuthorityGraph:
    roles: List[str]
    edges: List[AuthorityEdge]
    sinks: List[Sink]
    setters: List[Setter]

    @classmethod
    def from_dict(cls, d: Dict[str, object]) -> "AuthorityGraph":
        return cls(
            roles=list(d.get("roles", [])),
            edges=[AuthorityEdge(**e) if isinstance(e, dict) else e for e in d.get("edges", [])],
            sinks=[Sink.from_dict(s) if isinstance(s, dict) else s for s in d.get("sinks", [])],
            setters=[Setter.from_dict(s) if isinstance(s, dict) else s for s in d.get("setters", [])],
        )


# ── Dependency graph domain ───────────────────────────────────────────────────

@dataclass
class ExternalDependency:
    type: str  # "oracle" | "proxy" | "callback" | "bridge" | ...
    from_: Optional[str]
    to: Optional[str]
    is_recovery_critical: Optional[bool]

    @classmethod
    def from_dict(cls, d: Dict[str, object]) -> "ExternalDependency":
        return cls(
            type=str(d.get("type", "")),
            from_=str(d["from"]) if d.get("from") else None,
            to=str(d["to"]) if d.get("to") else None,
            is_recovery_critical=bool(d["is_recovery_critical"]) if d.get("is_recovery_critical") is not None else None,
        )


@dataclass
class DependencyGraph:
    dependencies: List[ExternalDependency]

    @classmethod
    def from_dict(cls, d: Dict[str, object]) -> "DependencyGraph":
        return cls(
            dependencies=[ExternalDependency.from_dict(dep) if isinstance(dep, dict) else dep for dep in d.get("dependencies", [])],
        )


# ── Action / state transition domain ─────────────────────────────────────────

@dataclass
class StateTransition:
    path: str
    contract: str
    function: str
    writes_state: bool
    reads_state: bool
    calls_external: bool
    changes_authority: bool
    touches_sink: bool
    keywords: List[str]


@dataclass
class Action:
    path: str
    contract: str
    function: str
    visibility: str
    writes: List[str]
    state_reads: List[str]
    external_calls: List[str]
    internal_calls: List[str]
    reads: List[str]
    auth_guards: List[str]
    require_guards: List[str]
    modifiers: List[str]
    sink_hints: List[str]
    state_keywords: List[str]
    emits_value: bool
    trust_boundary: bool
    line_start: Optional[int]
    line_end: Optional[int]

    @classmethod
    def from_dict(cls, d: Dict[str, object]) -> "Action":
        return cls(
            path=str(d.get("path", "")),
            contract=str(d.get("contract", "")),
            function=str(d.get("function", "")),
            visibility=str(d.get("visibility", "")),
            writes=list(d.get("writes", [])),
            state_reads=list(d.get("state_reads", [])),
            external_calls=list(d.get("external_calls", [])),
            internal_calls=list(d.get("internal_calls", [])),
            reads=list(d.get("reads", [])),
            auth_guards=list(d.get("auth_guards", [])),
            require_guards=list(d.get("require_guards", [])),
            modifiers=list(d.get("modifiers", [])),
            sink_hints=list(d.get("sink_hints", [])),
            state_keywords=list(d.get("state_keywords", [])),
            emits_value=bool(d.get("emits_value", False)),
            trust_boundary=bool(d.get("trust_boundary", False)),
            line_start=int(d["line_start"]) if d.get("line_start") else None,
            line_end=int(d["line_end"]) if d.get("line_end") else None,
        )


# ── Finding domain ─────────────────────────────────────────────────────────────

@dataclass
class InvariantCandidate:
    name: str
    expression: str
    source_path: str
    confidence: float

    @classmethod
    def from_dict(cls, d: Dict[str, object]) -> "InvariantCandidate":
        return cls(
            name=str(d.get("name", "")),
            expression=str(d.get("expression", "")),
            source_path=str(d.get("source_path", "")),
            confidence=float(d.get("confidence", 0.0)),
        )


@dataclass
class EvidenceItem:
    setter: Optional[Dict[str, object]]
    sink: Optional[Dict[str, object]]
    setters: Optional[List[Dict[str, object]]]
    shared_writes: List[str]
    slot: Optional[str]
    slot_type: Optional[str]
    bound_types: List[str]


@dataclass
class FindingCandidate:
    id: str
    family: str  # "authority_drift" | "callback_state_drift" | ...
    title: str
    target_contract: str
    target_functions: List[str]
    evidence: List[EvidenceItem]
    violated_invariant: str
    confidence_score: float
    blocking_unknowns: List[str]

    @classmethod
    def from_dict(cls, d: Dict[str, object]) -> "FindingCandidate":
        def _ev(e: Dict[str, object]) -> EvidenceItem:
            return EvidenceItem(
                setter=dict(e["setter"]) if e.get("setter") else None,
                sink=dict(e["sink"]) if e.get("sink") else None,
                setters=[dict(s) for s in e["setters"]] if e.get("setters") else None,
                shared_writes=list(e.get("shared_writes", [])),
                slot=str(e["slot"]) if e.get("slot") else None,
                slot_type=str(e["slot_type"]) if e.get("slot_type") else None,
                bound_types=list(e.get("bound_types", [])),
            )

        return cls(
            id=str(d.get("id", "")),
            family=str(d.get("family", "")),
            title=str(d.get("title", "")),
            target_contract=str(d.get("target_contract", "")),
            target_functions=list(d.get("target_functions", [])),
            evidence=[_ev(e) if isinstance(e, dict) else e for e in d.get("evidence", [])],
            violated_invariant=str(d.get("violated_invariant", "")),
            confidence_score=float(d.get("confidence_score", 0.5)),
            blocking_unknowns=list(d.get("blocking_unknowns", [])),
        )


@dataclass
class FindingConfirmation:
    candidate_id: str
    title: str
    status: str  # "source_confirmed" | "weak_signal" | "rejected"
    rejection_reason: Optional[str]
    scope_status: str  # "in_scope" | "out_of_scope" | "unknown"
    confidence_score: float
    confidence_boost: float
    source_paths: List[str]
    sink_function: str
    guard_analysis: str
    state_argument: str
    disqualifiers: List[str]

    @classmethod
    def from_dict(cls, d: Dict[str, object]) -> "FindingConfirmation":
        return cls(
            candidate_id=str(d.get("candidate_id", "")),
            title=str(d.get("title", "")),
            status=str(d.get("status", "weak_signal")),
            rejection_reason=str(d["rejection_reason"]) if d.get("rejection_reason") else None,
            scope_status=str(d.get("scope_status", "unknown")),
            confidence_score=float(d.get("confidence_score", 0.5)),
            confidence_boost=float(d.get("confidence_boost", 0.0)),
            source_paths=list(d.get("source_paths", [])),
            sink_function=str(d.get("sink_function", "")),
            guard_analysis=str(d.get("guard_analysis", "")),
            state_argument=str(d.get("state_argument", "")),
            disqualifiers=list(d.get("disqualifiers", [])),
        )


@dataclass
class ProofPlan:
    finding_id: str
    title: str
    family: str
    status: str
    confirmability: str  # "confirmable_and_reproducible" | "confirmable_but_weak" | "interesting_but_unconfirmed"
    reproducibility_signal: str
    false_positive_risk: str
    confidence_score: float
    confidence_boost: float
    rejection_reason: Optional[str]
    scope_status: str
    guard_analysis: str
    blocking_assumptions: List[str]
    harness_candidates: List[str]
    required_actors: List[str]
    setup_requirements: List[str]
    transaction_sequence: List[str]
    assertions: List[str]
    expected_outcome: str
    preferred_test_path: str
    minimum_test_commands: List[str]

    @classmethod
    def from_dict(cls, d: Dict[str, object]) -> "ProofPlan":
        return cls(
            finding_id=str(d.get("finding_id", "")),
            title=str(d.get("title", "")),
            family=str(d.get("family", "")),
            status=str(d.get("status", "")),
            confirmability=str(d.get("confirmability", "")),
            reproducibility_signal=str(d.get("reproducibility_signal", "unknown")),
            false_positive_risk=str(d.get("false_positive_risk", "unknown")),
            confidence_score=float(d.get("confidence_score", 0.5)),
            confidence_boost=float(d.get("confidence_boost", 0.0)),
            rejection_reason=str(d["rejection_reason"]) if d.get("rejection_reason") else None,
            scope_status=str(d.get("scope_status", "unknown")),
            guard_analysis=str(d.get("guard_analysis", "")),
            blocking_assumptions=list(d.get("blocking_assumptions", [])),
            harness_candidates=list(d.get("harness_candidates", [])),
            required_actors=list(d.get("required_actors", [])),
            setup_requirements=list(d.get("setup_requirements", [])),
            transaction_sequence=list(d.get("transaction_sequence", [])),
            assertions=list(d.get("assertions", [])),
            expected_outcome=str(d.get("expected_outcome", "")),
            preferred_test_path=str(d.get("preferred_test_path", "")),
            minimum_test_commands=list(d.get("minimum_test_commands", [])),
        )


# ── Typed load helpers ─────────────────────────────────────────────────────────

def read_json(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def load_semantic_index(path: Optional[Path] = None) -> SemanticIndex:
    data = read_json(path or (AUDIT_DIR / "semantic_index.json"))
    ast_path = AUDIT_DIR / "ast_semantic_index.json"
    if ast_path.exists():
        ast_data = read_json(ast_path)
        if ast_data.get("_ast_mode"):
            return SemanticIndex.from_dict(ast_data)
    return SemanticIndex.from_dict(data)


def load_authority_graph(path: Optional[Path] = None) -> AuthorityGraph:
    data = read_json(path or (AUDIT_DIR / "authority_graph.json"))
    return AuthorityGraph.from_dict(data)


def load_dependency_graph(path: Optional[Path] = None) -> DependencyGraph:
    data = read_json(path or (AUDIT_DIR / "dependency_graph.json"))
    return DependencyGraph.from_dict(data)


def load_action_catalog(path: Optional[Path] = None) -> List[Action]:
    data = read_json(path or (AUDIT_DIR / "action_catalog.json"))
    return [Action.from_dict(a) if isinstance(a, dict) else a for a in data.get("actions", [])]


def load_state_transitions(path: Optional[Path] = None) -> List[StateTransition]:
    data = read_json(path or (AUDIT_DIR / "state_transition_map.json"))
    return [StateTransition(**t) if isinstance(t, dict) else t for t in data.get("transitions", [])]


def load_invariant_candidates(path: Optional[Path] = None) -> List[InvariantCandidate]:
    data = read_json(path or (AUDIT_DIR / "invariant_candidates.json"))
    return [InvariantCandidate.from_dict(i) if isinstance(i, dict) else i for i in data.get("invariants", [])]


def load_finding_candidates(path: Optional[Path] = None) -> List[FindingCandidate]:
    data = read_json(path or (AUDIT_DIR / "finding_candidates.json"))
    return [FindingCandidate.from_dict(f) if isinstance(f, dict) else f for f in data.get("findings", [])]


def load_confirmations(path: Optional[Path] = None) -> List[FindingConfirmation]:
    data = read_json(path or (AUDIT_DIR / "finding_confirmations.json"))
    return [FindingConfirmation.from_dict(c) if isinstance(c, dict) else c for c in data.get("findings", [])]


def load_proof_plans(path: Optional[Path] = None) -> List[ProofPlan]:
    data = read_json(path or (AUDIT_DIR / "proof_plans.json"))
    return [ProofPlan.from_dict(p) if isinstance(p, dict) else p for p in data.get("proof_plans", [])]


def load_repair_log(path: Optional[Path] = None) -> List[RepairEvent]:
    data = read_json(path or (AUDIT_DIR / "repair_log.json"))
    return [RepairEvent.from_dict(e) if isinstance(e, dict) else e for e in data.get("events", [])]
