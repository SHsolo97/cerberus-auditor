"""
cerberus_common.io — File I/O, status management, and phase validation.

Depends on types.py and toolchain.py for path constants and CommandResult.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from . import types as _t
from . import toolchain as _tc

# ── Lazy AUDIT_DIR resolution ─────────────────────────────────────────────────
# .audit_board is anchored to the target codebase's project root, not the CWD.
# set_audit_dir(target_dir) sets it; get_audit_dir() returns the current value.
# __getattr__ makes "from cerberus_common.io import AUDIT_DIR" always get the live value.

_audit_dir_global: Optional[Path] = None


def get_audit_dir() -> Path:
    """Return .audit_board anchored to the target's project root.

    Auto-detects project root on first call. Once set via set_audit_dir(),
    subsequent calls return the cached value.
    """
    global _audit_dir_global
    if _audit_dir_global is None:
        _audit_dir_global = _tc.find_project_root(_tc.get_skill_root()) / ".audit_board"
    return _audit_dir_global


def set_audit_dir(target_dir: Path) -> None:
    """Explicitly set .audit_board relative to the given target directory's project root."""
    global _audit_dir_global
    _audit_dir_global = _tc.find_project_root(target_dir) / ".audit_board"


def ensure_audit_dir() -> None:
    """Ensure the .audit_board directory exists."""
    get_audit_dir().mkdir(parents=True, exist_ok=True)


def ensure_meta_dir() -> None:
    """Ensure the meta/ directory exists."""
    _tc.META_DIR().mkdir(parents=True, exist_ok=True)


def __getattr__(name: str) -> Any:
    if name == "AUDIT_DIR":
        return get_audit_dir()
    if name == "STATUS_FILE":
        return get_audit_dir() / "status.json"
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

# ── File I/O ───────────────────────────────────────────────────────────────────

def write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd, tmp_path_str = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.tmp_")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_handle:
                tmp_handle.write(content)
                tmp_handle.flush()
                os.fsync(tmp_handle.fileno())
        except Exception:
            try:
                os.unlink(tmp_path_str)
            except OSError:
                pass
            raise
        os.replace(tmp_path_str, path)
    except OSError:
        path.write_text(content, encoding="utf-8")


def read_text_file(path: Path) -> str:
    _MAX_SOL_FILE_BYTES = 10 * 1024 * 1024
    try:
        if path.stat().st_size > _MAX_SOL_FILE_BYTES:
            return ""
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def read_json(path: Path) -> Dict[str, Any]:
    return _t.read_json(path)


def write_status(status: _t.PhaseStatus) -> None:
    get_audit_dir().mkdir(parents=True, exist_ok=True)
    data = _t.read_json(get_audit_dir() / "status.json")
    data[status.phase] = status.to_dict()
    get_audit_dir() / "status.json".write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def emit_status(status: _t.PhaseStatus) -> None:
    print(json.dumps(status.to_dict(), indent=2, sort_keys=True))


# ── Markdown helpers ────────────────────────────────────────────────────────────

_MARKDOWN_PLACEHOLDER_PATTERNS = ("todo", "placeholder", "tbd")


def markdown_has_substantive_bullets(path: Path) -> bool:
    content = read_text_file(path)
    if not content:
        return False
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped.startswith("- "):
            continue
        normalized = stripped[2:].strip().lower()
        if normalized and not any(token in normalized for token in _MARKDOWN_PLACEHOLDER_PATTERNS):
            return True
    return False


def markdown_has_substantive_content(path: Path) -> bool:
    content = read_text_file(path)
    if not content:
        return False
    if markdown_has_substantive_bullets(path):
        return True
    substantive_lines = 0
    for line in content.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith("```"):
            continue
        lowered = stripped.lower()
        if any(token in lowered for token in _MARKDOWN_PLACEHOLDER_PATTERNS):
            continue
        if len(stripped) >= 24:
            substantive_lines += 1
        if substantive_lines >= 2:
            return True
    return False


def markdown_has_explicit_reason(path: Path) -> bool:
    content = read_text_file(path)
    if not content:
        return False
    lowered = content.lower()
    return "not determined" in lowered or "no native validation hits" in lowered or "no exploit-family heuristics" in lowered


def strip_solidity_comments(content: str) -> str:
    content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
    content = re.sub(r"//.*", "", content)
    return content


def file_has_concrete_contract(path: Path) -> bool:
    return any(item["kind"] == "contract" for item in extract_contract_declarations(path))


# ── Regex helpers (source analysis) ─────────────────────────────────────────────

CONTRACT_DECLARATION_PATTERN = re.compile(
    r"^\s*(?:(abstract)\s+)?(contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)\b"
)
IMPORT_PATTERN = re.compile(r'^\s*import\s+(?:(?:[^"]+)\s+from\s+)?"([^"]+)"\s*;')
INHERITANCE_PATTERN = re.compile(
    r"^\s*(?:(abstract)\s+)?contract\s+([A-Za-z_][A-Za-z0-9_]*)\s+is\s+([^{]+)\{?"
)


def extract_contract_declarations(path: Path) -> List[Dict[str, Any]]:
    declarations: List[Dict[str, Any]] = []
    content = read_text_file(path)
    if not content:
        return declarations
    for line in content.splitlines():
        match = CONTRACT_DECLARATION_PATTERN.match(line)
        if not match:
            continue
        declarations.append(
            {
                "kind": "abstract contract" if match.group(1) else match.group(2),
                "name": match.group(3),
            }
        )
    return declarations


def extract_imports(path: Path) -> List[str]:
    imports: List[str] = []
    content = read_text_file(path)
    if not content:
        return imports
    for line in content.splitlines():
        match = IMPORT_PATTERN.match(line)
        if match:
            imports.append(match.group(1))
    return imports


def extract_inheritance(path: Path) -> List[tuple[str, List[str]]]:
    edges: List[tuple[str, List[str]]] = []
    content = read_text_file(path)
    if not content:
        return edges
    for line in content.splitlines():
        match = INHERITANCE_PATTERN.match(line)
        if not match:
            continue
        parents = [part.strip().split("(")[0].strip() for part in match.group(3).split(",")]
        parents = [parent for parent in parents if parent]
        edges.append((match.group(2), parents))
    return edges


def select_primary_contract(files: List[Path]) -> Optional[Path]:
    if not files:
        return None

    entrypoint_names = {
        "vault", "evault", "router", "manager", "factory",
        "market", "pool", "engine", "core", "protocol",
    }

    def score(path: Path) -> tuple[int, int, int, int, str]:
        lowered = str(path).lower()
        declarations = extract_contract_declarations(path)
        concrete_contracts = [item for item in declarations if item["kind"] == "contract"]
        contract_names = [str(item["name"]).lower() for item in concrete_contracts]

        penalty = 0
        for token in ("/test/", "/script/", "/interfaces/", "/interface/", "mock", ".t.sol"):
            if token in lowered:
                penalty += 4
        for token in ("/shared/", "/lib/", "/libs/", "/utils/"):
            if token in lowered:
                penalty += 1
        if path.name.lower().startswith("i") and len(path.stem) > 1 and path.stem[1:2].isupper():
            penalty += 3
        if not concrete_contracts:
            penalty += 6

        entrypoint_bonus = 0
        for name in contract_names:
            if name in entrypoint_names:
                entrypoint_bonus += 3
            for keyword in entrypoint_names:
                if keyword in name:
                    entrypoint_bonus += 1

        inheritance_bonus = 0
        for _name, parents in extract_inheritance(path):
            inheritance_bonus += len(parents)

        try:
            size = path.stat().st_size
        except OSError:
            size = 0

        return (penalty, -entrypoint_bonus, -inheritance_bonus, -size, lowered)

    return sorted(files, key=score)[0]


# ── Solidity flattening ─────────────────────────────────────────────────────────

def concat_imports(
    primary_path: Path,
    project_root: Path,
    *,
    seen: Optional[Set[Path]] = None,
    max_depth: int = 32,
) -> str:
    if seen is None:
        seen = set()

    spdx_seen = False
    pragma_seen = False
    output_lines: List[str] = []

    def _resolve_import(import_str: str, from_path: Path) -> Optional[Path]:
        import_str = import_str.strip()
        if not import_str:
            return None

        if import_str.startswith("./") or import_str.startswith("../"):
            base_dir = from_path.parent
            raw = base_dir / import_str
            for candidate in (raw, raw.with_suffix(".sol"), raw.parent / "index.sol"):
                if candidate.exists() and candidate.is_file():
                    return candidate
            index_candidate = base_dir / import_str.lstrip("./") / "index.sol"
            if index_candidate.exists() and index_candidate.is_file():
                return index_candidate
            return raw if raw.exists() else None

        for base in (project_root, project_root / "node_modules"):
            if not base.is_dir():
                continue
            parts = import_str.lstrip("/").split("/", 2)
            if import_str.startswith("@"):
                if len(parts) >= 3:
                    package_root = base / parts[0] / parts[1]
                    rel_path = parts[2] if len(parts) > 2 else ""
                    candidate = package_root / rel_path
                    for candidate in (candidate, candidate.with_suffix(".sol"), package_root / "index.sol"):
                        if candidate.exists() and candidate.is_file():
                            return candidate
            else:
                candidate = base / import_str
                for candidate in (candidate, candidate.with_suffix(".sol")):
                    if candidate.exists() and candidate.is_file():
                        return candidate
                index_candidate = base / import_str.lstrip("/") / "index.sol"
                if index_candidate.exists() and index_candidate.is_file():
                    return index_candidate
        return None

    def _walk(path: Path, depth: int = 0) -> None:
        nonlocal spdx_seen, pragma_seen
        if depth > max_depth:
            return
        resolved = path.resolve()
        if resolved in seen:
            return
        seen.add(resolved)

        content = read_text_file(resolved)
        if not content:
            return

        output_lines.append(f"// ── {resolved.name} ──────────────────────────────────────────────")
        output_lines.append("")

        for line in content.splitlines():
            if re.match(r"^\s*//\s*SPDX-License-Identifier:", line):
                if spdx_seen:
                    continue
                spdx_seen = True
            if re.match(r"^\s*pragma\s+solidity\b", line):
                if pragma_seen:
                    continue
                pragma_seen = True

            stripped = line.strip()
            import_match = re.match(r'^\s*import\s+(?:(?:[^";]+)\s+from\s+)?["\']([^"\']+)["\']\s*;', line)
            if import_match:
                resolved_import = _resolve_import(import_match.group(1), path)
                if resolved_import and resolved_import not in seen:
                    _walk(resolved_import, depth + 1)
                continue

            bare_import_match = re.match(r'^\s*import\s+["\']([^"\']+)["\']\s*;', line)
            if bare_import_match and not import_match:
                resolved_import = _resolve_import(bare_import_match.group(1), path)
                if resolved_import and resolved_import not in seen:
                    _walk(resolved_import, depth + 1)
                continue

            output_lines.append(line)

    _walk(primary_path.resolve())
    return "\n".join(output_lines) + "\n"


def dedupe_flattened_solidity(content: str) -> str:
    spdx_seen = False
    pragma_seen = False
    out: List[str] = []
    for line in content.splitlines():
        if re.match(r"^\s*//\s*SPDX-License-Identifier:", line):
            if spdx_seen:
                continue
            spdx_seen = True
        if re.match(r"^\s*pragma\s+solidity\b", line):
            if pragma_seen:
                continue
            pragma_seen = True
        out.append(line)
    return "\n".join(out) + ("\n" if out else "")


# ── Utility ─────────────────────────────────────────────────────────────────────

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def make_failure_status(
    phase: str,
    *,
    errors: List[str],
    warnings: Optional[List[str]] = None,
    artifacts: Optional[Dict[str, str]] = None,
    details: Optional[Dict[str, Any]] = None,
    mode: str = "degraded",
) -> _t.PhaseStatus:
    return _t.PhaseStatus(
        phase=phase,
        ok=False,
        mode=mode,
        artifacts=artifacts or {},
        warnings=warnings or [],
        errors=errors,
        details=details or {},
    )


def fatal_status(
    phase: str,
    exc: BaseException,
    *,
    warnings: Optional[List[str]] = None,
    artifacts: Optional[Dict[str, str]] = None,
    details: Optional[Dict[str, Any]] = None,
) -> _t.PhaseStatus:
    return make_failure_status(
        phase,
        errors=[f"Unhandled exception: {type(exc).__name__}: {exc}"],
        warnings=warnings,
        artifacts=artifacts,
        details=details,
    )


# ── Phase validation ───────────────────────────────────────────────────────────

def validate_phase_outputs(status: _t.PhaseStatus) -> _t.PhaseStatus:
    errors = list(status.errors)
    artifacts = status.artifacts if isinstance(status.artifacts, dict) else {}

    if status.phase == "preflight_or_repair":
        repair_log = Path(str(artifacts.get("repair_log", get_audit_dir() / "repair_log.json")))
        repair_data = _t.read_json(repair_log)
        events = repair_data.get("events") if isinstance(repair_data, dict) else None
        if not isinstance(events, list):
            errors.append("repair_log.json must contain a top-level events array.")

    if status.phase == "ast_semantic_index":
        ast_path = Path(str(artifacts.get("ast_semantic_index", get_audit_dir() / "ast_semantic_index.json")))
        ast_data = _t.read_json(ast_path)
        if not ast_data.get("_ast_mode"):
            errors.append("ast_semantic_index.json must have _ast_mode: true.")
        files = ast_data.get("files") if isinstance(ast_data, dict) else None
        if not isinstance(files, list) or not files:
            errors.append("ast_semantic_index.json must contain at least one file entry.")
        elif not any(isinstance(f, dict) and f.get("functions") for f in files):
            errors.append("ast_semantic_index.json must contain at least one file entry with at least one function.")

    if status.phase == "semantic_index":
        semantic_path = Path(str(artifacts.get("semantic_index", get_audit_dir() / "semantic_index.json")))
        semantic_data = _t.read_json(semantic_path)
        contracts = semantic_data.get("contracts") if isinstance(semantic_data, dict) else None
        files = semantic_data.get("files") if isinstance(semantic_data, dict) else None
        if not isinstance(contracts, list) or not contracts:
            errors.append("semantic_index.json must contain at least one indexed contract.")
        if not isinstance(files, list) or not files:
            errors.append("semantic_index.json must contain indexed file entries.")

    if status.phase == "action_catalog":
        action_path = Path(str(artifacts.get("action_catalog", get_audit_dir() / "action_catalog.json")))
        transition_path = Path(str(artifacts.get("state_transition_map", get_audit_dir() / "state_transition_map.json")))
        actions = _t.read_json(action_path).get("actions")
        transitions = _t.read_json(transition_path).get("transitions")
        if not isinstance(actions, list) or not actions:
            errors.append("action_catalog.json must contain at least one action.")
        if not isinstance(transitions, list):
            errors.append("state_transition_map.json must contain a top-level transitions array.")

    if status.phase == "authority_graph":
        graph_path = Path(str(artifacts.get("authority_graph", get_audit_dir() / "authority_graph.json")))
        graph = _t.read_json(graph_path)
        sinks = graph.get("sinks") if isinstance(graph, dict) else None
        if not isinstance(sinks, list):
            errors.append("authority_graph.json must contain a top-level sinks array.")

    if status.phase == "dependency_graph":
        dep_path = Path(str(artifacts.get("dependency_graph", get_audit_dir() / "dependency_graph.json")))
        dependencies = _t.read_json(dep_path).get("dependencies")
        if not isinstance(dependencies, list):
            errors.append("dependency_graph.json must contain a top-level dependencies array.")

    if status.phase == "invariant_candidates":
        invariant_path = Path(str(artifacts.get("invariant_candidates", get_audit_dir() / "invariant_candidates.json")))
        invariants = _t.read_json(invariant_path).get("invariants")
        if not isinstance(invariants, list) or not invariants:
            errors.append("invariant_candidates.json must contain at least one invariant candidate.")

    if status.phase == "finding_candidates":
        finding_path = Path(str(artifacts.get("finding_candidates", get_audit_dir() / "finding_candidates.json")))
        findings = _t.read_json(finding_path).get("findings")
        if not isinstance(findings, list):
            errors.append("finding_candidates.json must contain a top-level findings array.")
        elif findings and not all(
            isinstance(item, dict)
            and str(item.get("family", "")).strip()
            and str(item.get("violated_invariant", "")).strip()
            and isinstance(item.get("target_functions", []), list)
            for item in findings
        ):
            errors.append("finding_candidates.json contains an incomplete finding candidate.")

    if status.phase == "finding_confirmation":
        confirm_path = Path(str(artifacts.get("finding_confirmations", get_audit_dir() / "finding_confirmations.json")))
        findings = _t.read_json(confirm_path).get("findings")
        if not isinstance(findings, list):
            errors.append("finding_confirmations.json must contain a top-level findings array.")
        elif findings and not all(
            isinstance(item, dict)
            and str(item.get("status", "")) in {"rejected", "weak_signal", "source_confirmed", "proof_ready"}
            and str(item.get("state_argument", "")).strip()
            for item in findings
        ):
            errors.append("finding_confirmations.json contains an invalid confirmation entry.")

    if status.phase == "proof_planning":
        plan_path = Path(str(artifacts.get("proof_plans", get_audit_dir() / "proof_plans.json")))
        plans = _t.read_json(plan_path).get("proof_plans")
        if not isinstance(plans, list):
            errors.append("proof_plans.json must contain a top-level proof_plans array.")
        elif plans and not all(
            isinstance(item, dict)
            and isinstance(item.get("harness_candidates", []), list)
            and isinstance(item.get("transaction_sequence", []), list)
            and isinstance(item.get("assertions", []), list)
            for item in plans
        ):
            errors.append("proof_plans.json contains an invalid proof plan entry.")

    if status.phase in {"architecture", "state_vectors"}:
        required = (
            get_audit_dir() / "01_threat_model.md",
            get_audit_dir() / "02_static_analysis.md",
            get_audit_dir() / "03_attack_vectors.md",
        )
        weak = [str(path) for path in required if not markdown_has_substantive_bullets(path)]
        if weak:
            errors.append("Required markdown artifacts are missing substantive populated entries: " + ", ".join(weak))

    if status.phase == "rule_scan":
        rule_scan_md = Path(str(artifacts.get("rule_scan_md", get_audit_dir() / "rule_scan.md")))
        exploit_md = Path(str(artifacts.get("exploit_rankings", get_audit_dir() / "exploit_rankings.md")))
        if not (markdown_has_substantive_bullets(rule_scan_md) or markdown_has_explicit_reason(rule_scan_md)):
            errors.append("rule_scan.md lacks scoped findings or an explicit not-determined reason.")
        if not (markdown_has_substantive_bullets(exploit_md) or markdown_has_explicit_reason(exploit_md)):
            errors.append("exploit_rankings.md lacks ranked families or an explicit not-determined reason.")

    if status.phase == "hypothesis_triage":
        hypotheses_md = Path(str(artifacts.get("exploit_hypotheses", get_audit_dir() / "exploit_hypotheses.md")))
        proof_status = Path(str(artifacts.get("proof_status", get_audit_dir() / "proof_status.json")))
        if not (markdown_has_substantive_content(hypotheses_md) or markdown_has_explicit_reason(hypotheses_md)):
            errors.append("exploit_hypotheses.md lacks concrete hypotheses or an explicit not-determined reason.")
        proof_data = _t.read_json(proof_status)
        findings = proof_data.get("findings") if isinstance(proof_data, dict) else None
        if not isinstance(findings, list):
            errors.append("proof_status.json must contain a top-level findings array.")
        elif findings:
            valid_statuses = {"hypothesis", "source_confirmed", "locally_reproduced", "deterministic_poc", "submission_ready"}
            if not all(isinstance(item, dict) and str(item.get("status", "")) in valid_statuses for item in findings):
                errors.append("proof_status.json contains a finding without a valid proof-maturity status.")

    if status.phase == "poc_design":
        poc_spec = Path(str(artifacts.get("poc_spec", get_audit_dir() / "poc_spec.md")))
        severity_md = Path(str(artifacts.get("severity_assessment", get_audit_dir() / "severity_assessment.md")))
        submission_md = Path(str(artifacts.get("submission_notes", get_audit_dir() / "submission_notes.md")))
        if not markdown_has_substantive_content(poc_spec):
            errors.append("poc_spec.md lacks a concrete harness or assertion plan.")
        else:
            poc_text = read_text_file(poc_spec).lower()
            if "candidate test file:" not in poc_text and "suggested run command" not in poc_text:
                errors.append("poc_spec.md must name a harness candidate or a focused run command.")
        if not markdown_has_substantive_content(severity_md):
            errors.append("severity_assessment.md lacks severity reasoning.")
        if not markdown_has_substantive_content(submission_md):
            errors.append("submission_notes.md lacks a contest-ready report outline.")

    if status.phase == "scaffold_tests":
        compiled = bool(status.details.get("compile_check_passed")) if isinstance(status.details, dict) else False
        if not compiled:
            errors.append("Generated scaffolds were written but did not pass the compile check.")

    if status.phase == "submission_bundle":
        manifest = Path(str(artifacts.get("manifest", get_audit_dir() / "PoC" / "final_submission" / "MANIFEST.md")))
        if not markdown_has_substantive_content(manifest):
            errors.append("Submission bundle manifest is missing or lacks concrete contents.")

    if errors != status.errors:
        status.errors = errors
        status.ok = False
        if status.mode == "full":
            status.mode = "degraded"
    return status


# ── Auto-log callback ───────────────────────────────────────────────────────────
# Registered by improvement.py to avoid a circular import.

_auto_log_fn: Optional[Callable[[_t.PhaseStatus], None]] = None


def register_auto_log_fn(fn: Callable[[_t.PhaseStatus], None]) -> None:
    """Called by improvement.py at import time to register the auto-log callback."""
    global _auto_log_fn
    _auto_log_fn = fn


# ── Finalize ───────────────────────────────────────────────────────────────────

def finalize(status: _t.PhaseStatus, exit_code: Optional[int] = None) -> int:
    status = validate_phase_outputs(status)
    write_status(status)
    run_id_value = status.details.get("run_id") if isinstance(status.details, dict) else None
    run_id = str(run_id_value) if run_id_value else None
    if _auto_log_fn is not None:
        _auto_log_fn(status, run_id=run_id)
    emit_status(status)
    if exit_code is not None:
        return exit_code
    return 0 if status.ok else 1
