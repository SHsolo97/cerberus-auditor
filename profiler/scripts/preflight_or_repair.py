from __future__ import annotations

import argparse
import json
import os
import py_compile
import re
import tempfile
from pathlib import Path
from typing import List, Optional

from common import (
    AUDIT_DIR,
    PhaseStatus,
    RepairEvent,
    finalize,
    make_failure_status,
    read_json,
    set_audit_dir,
    utc_now_iso,
    write_text,
)


# ── Helpers ────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Preflight-check and optionally repair a Cerberus script before a phase runs.")
    parser.add_argument("--phase-name", required=True, help="Phase that is about to run.")
    parser.add_argument("--script-path", required=True, help="Path to the script that powers the phase.")
    parser.add_argument("--target-dir", default=".", help="Audit target directory.")
    return parser.parse_args()


def _build_event(
    phase_name: str,
    script_path: Path,
    decision: str,
    failure_kind: Optional[str],
    evidence: List[str],
    patch_applied: bool = False,
    patch_content: Optional[str] = None,
    retry_count: int = 0,
    root_cause: Optional[str] = None,
) -> dict:
    return {
        "phase": phase_name,
        "script": str(script_path),
        "decision": decision,
        "failure_kind": failure_kind,
        "evidence": evidence,
        "timestamp": utc_now_iso(),
        "patch_applied": patch_applied,
        "patch_content": patch_content,
        "retry_count": retry_count,
        "root_cause": root_cause,
    }


def _write_events(events: List[dict], repair_log_path: Path) -> None:
    write_text(repair_log_path, json.dumps({"events": events}, indent=2) + "\n")


def _load_events(repair_log_path: Path) -> List[dict]:
    data = read_json(repair_log_path)
    events = data.get("events") if isinstance(data, dict) else None
    return list(events) if isinstance(events, list) else []


# ── Artifact validation ───────────────────────────────────────────────────────

# Mapping from phase name -> (artifact key, placeholder marker)
_PHASE_ARTIFACT_MAP = {
    "semantic_index": ("semantic_index", "[]"),
    "ast_semantic_index": ("ast_semantic_index", "[]"),
    "action_catalog": ("action_catalog", '{"actions": []}'),
    "authority_graph": ("authority_graph", '{"roles": [], "edges": [], "sinks": []}'),
    "dependency_graph": ("dependency_graph", '{"dependencies": []}'),
    "state_transition_map": ("state_transition_map", '{"transitions": []}'),
    "invariant_candidates": ("invariant_candidates", '{"invariants": []}'),
    "finding_candidates": ("finding_candidates", '{"findings": []}'),
    "finding_confirmations": ("finding_confirmations", '{"findings": []}'),
    "proof_plans": ("proof_plans", '{"proof_plans": []}'),
}

_CRITICAL_PHASES = {
    "semantic_index",
    "ast_semantic_index",
    "action_catalog",
    "authority_graph",
    "dependency_graph",
    "rule_scan",
    "invariant_candidates",
    "finding_candidates",
}


def _check_previous_phase_artifact(phase_name: str, target_dir: Path) -> tuple[str, List[str]]:
    """
    Returns (decision, list of evidence messages).
    Checks if the phase's previous run produced a usable artifact.
    """
    if phase_name not in _PHASE_ARTIFACT_MAP:
        return "resume", []

    artifact_key, _ = _PHASE_ARTIFACT_MAP[phase_name]
    status_path = AUDIT_DIR / "status.json"
    status_data = read_json(status_path)

    phase_status = status_data.get(phase_name) if isinstance(status_data, dict) else None
    if phase_status is None:
        # No previous run — nothing to validate
        return "resume", []

    phase_ok = phase_status.get("ok", False)
    artifacts = phase_status.get("artifacts", {})
    artifact_rel = artifacts.get(artifact_key)
    if not artifact_rel:
        return "resume", []

    artifact_path = Path(artifact_rel) if Path(artifact_rel).is_absolute() else (target_dir / artifact_rel)
    if not artifact_path.exists():
        if phase_name in _CRITICAL_PHASES:
            return "stop_and_escalate", [
                f"Previous phase '{phase_name}' reported ok but artifact is missing: {artifact_path}"
            ]
        return "skip_phase", [f"Previous phase '{phase_name}' artifact missing; skipping phase."]

    try:
        content = artifact_path.read_text(encoding="utf-8")
    except OSError as exc:
        return "stop_and_escalate", [f"Could not read artifact: {exc}"]

    _, placeholder_marker = _PHASE_ARTIFACT_MAP[phase_name]
    # Normalize: strip whitespace so "  []  \n" matches "[]"
    content_normalized = content.strip()
    placeholder_normalized = placeholder_marker.strip()
    # Check exact match so "[]" substring in real JSON doesn't false-positive
    is_stub = content_normalized == placeholder_normalized
    if is_stub:
        if phase_name in _CRITICAL_PHASES:
            return "stop_and_escalate", [
                f"Previous phase '{phase_name}' produced only a stub artifact: {artifact_path}"
            ]
        return "skip_phase", [f"Previous phase '{phase_name}' artifact is still stub; skipping phase."]

    return "resume", []


# ── Patch engine ──────────────────────────────────────────────────────────────

# Simple token-level fixes for common Cerberus script bugs.
# Each entry: (regex pattern, replacement).  Applied line by line.
_LOCAL_FIXES: list[tuple[str, str]] = [
    # Fix missing 'from __future__ import annotations' at the top
    (
        r'^from common import \(.*?\)$',
        'from __future__ import annotations\nfrom common import ('
    ),
    # Fix trailing comma before close paren in multi-line import (common py_compile trap)
    (r',\s*\n(\s*from __future__)', r'\n\1'),
]


def _extract_line_from_py_compile_error(exc: py_compile.PyCompileError) -> tuple[Optional[int], Optional[str]]:
    """Parse line number and description from a PyCompileError."""
    msg = str(exc)
    m = re.search(r'line (\d+)', msg)
    lineno = int(m.group(1)) if m else None
    return lineno, msg


def _try_apply_local_fix(script_path: Path) -> tuple[bool, Optional[str], Optional[str]]:
    """
    Attempt a local patch on script_path.
    Returns (patched, root_cause, patch_content).
    """
    try:
        source = script_path.read_text(encoding="utf-8")
    except OSError:
        return False, None, None

    patched_lines = []
    applied_fixes: list[str] = []
    changed = False

    for i, line in enumerate(source.splitlines(), 1):
        original = line
        for pattern, replacement in _LOCAL_FIXES:
            if re.search(pattern, line):
                line = re.sub(pattern, replacement, line)
                applied_fixes.append(f"line {i}: {pattern!r}")
                changed = True
        patched_lines.append(line)

    if not changed:
        return False, None, None

    # Verify patched source compiles by writing to a temp file
    patched_content = "\n".join(patched_lines) + "\n"
    try:
        fd, tmp_path_str = tempfile.mkstemp(prefix=".preflight_patch_", suffix=".py")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(patched_content)
            py_compile.compile(tmp_path_str, doraise=True)
        finally:
            try:
                os.unlink(tmp_path_str)
            except OSError:
                pass
    except py_compile.PyCompileError:
        return False, None, None

    return True, f"local_fix:{'; '.join(applied_fixes)}", patched_content


def _apply_and_validate_patch(
    script_path: Path,
    failure_kind: str,
) -> tuple[bool, Optional[str], Optional[str]]:
    """
    Attempt to patch the script.
    Returns (patch_succeeded, root_cause, patch_content).
    """
    if failure_kind == "syntax_error":
        # Try local fixes first
        ok, root_cause, content = _try_apply_local_fix(script_path)
        if ok:
            return True, root_cause, content

    # No fix path available for this failure kind
    return False, None, None


# ── Smoke regression ─────────────────────────────────────────────────────────

def _smoke_regression(script_path: Path) -> bool:
    """Return True if script compiles without error."""
    try:
        py_compile.compile(str(script_path), doraise=True)
        return True
    except py_compile.PyCompileError:
        return False


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> int:
    args = parse_args()
    set_audit_dir(Path(args.target_dir))
    warnings: List[str] = []
    script_path = Path(args.script_path)
    target_dir = Path(args.target_dir)
    repair_log_path = AUDIT_DIR / "repair_log.json"

    events = _load_events(repair_log_path)

    event = _build_event(
        phase_name=args.phase_name,
        script_path=script_path,
        decision="resume",
        failure_kind=None,
        evidence=[],
    )

    # ── 1. Missing script ────────────────────────────────────────────────────
    if not script_path.exists():
        event["decision"] = "stop_and_escalate"
        event["failure_kind"] = "missing_script"
        event["evidence"].append(f"Missing script: {script_path}")
        events.append(event)
        _write_events(events, repair_log_path)
        status = make_failure_status(
            "preflight_or_repair",
            errors=[f"Phase script does not exist: {script_path}"],
            warnings=warnings,
            artifacts={"repair_log": str(repair_log_path)},
            details={
                "phase_name": args.phase_name,
                "script_path": str(script_path),
                "decision": event["decision"],
            },
        )
        return finalize(status)

    # ── 2. Syntax check ──────────────────────────────────────────────────────
    syntax_error: Optional[py_compile.PyCompileError] = None
    try:
        py_compile.compile(str(script_path), doraise=True)
    except py_compile.PyCompileError as exc:
        syntax_error = exc
        event["failure_kind"] = "syntax_error"
        event["evidence"].append(str(exc))
        lineno, _ = _extract_line_from_py_compile_error(exc)
        event["evidence"].append(f"Detected syntax error at line {lineno or 'unknown'}")

    # ── 3. Target directory ───────────────────────────────────────────────────
    if not target_dir.exists():
        warnings.append(f"Target directory does not exist yet: {target_dir}")
        event["evidence"].append(f"Target directory missing: {target_dir}")

    # ── 4. Attempt patch if syntax error ─────────────────────────────────────
    if syntax_error is not None:
        patched, root_cause, patch_content = _apply_and_validate_patch(
            script_path, "syntax_error"
        )
        event["patch_applied"] = patched
        event["patch_content"] = patch_content
        event["root_cause"] = root_cause

        if patched and patch_content is not None:
            # Write patched content back
            script_path.write_text(patch_content, encoding="utf-8")
            event["retry_count"] = 1

            # Smoke regression
            if _smoke_regression(script_path):
                event["decision"] = "resume"
                event["evidence"].append(
                    f"Syntax error patched and smoke check passed; resuming phase '{args.phase_name}'."
                )
            else:
                # Revert — patch didn't actually fix it
                event["decision"] = "stop_and_fix"
                event["evidence"].append(
                    "Patch applied but smoke check still fails; reverting patch and escalating."
                )
                # Restore original (best-effort; we kept patch_content so we could log it)
                try:
                    script_path.write_text(patch_content, encoding="utf-8")
                except OSError:
                    pass
        else:
            event["decision"] = "stop_and_fix"
            event["evidence"].append(
                "No local patch available for this syntax error; escalating for manual repair."
            )
    else:
        # ── 5. Artifact validation (no syntax error) ─────────────────────────
        artifact_decision, artifact_evidence = _check_previous_phase_artifact(
            args.phase_name, target_dir
        )
        event["evidence"].extend(artifact_evidence)
        if artifact_decision != "resume":
            event["decision"] = artifact_decision
            event["failure_kind"] = event["failure_kind"] or "artifact_missing_or_stub"

    events.append(event)
    _write_events(events, repair_log_path)

    ok = event["decision"] == "resume"
    status = PhaseStatus(
        phase="preflight_or_repair",
        ok=ok,
        mode="full" if ok else "degraded",
        artifacts={"repair_log": str(repair_log_path)},
        warnings=warnings,
        errors=[]
        if ok
        else [
            f"Preflight blocked phase '{args.phase_name}' "
            f"(decision: {event['decision']}). "
            f"See .audit_board/repair_log.json for details."
        ],
        details={
            "phase_name": args.phase_name,
            "script_path": str(script_path),
            "decision": event["decision"],
            "failure_kind": event["failure_kind"],
            "patch_applied": event["patch_applied"],
            "root_cause": event["root_cause"],
        },
    )
    return finalize(status)


if __name__ == "__main__":
    raise SystemExit(main())
