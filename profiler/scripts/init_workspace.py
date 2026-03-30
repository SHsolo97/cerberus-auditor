from __future__ import annotations

import argparse
from pathlib import Path
from typing import Dict, List

from common import (
    AUDIT_DIR,
    IMPROVEMENT_HOTSPOTS_FILE,
    IMPROVEMENT_LOG_FILE,
    IMPROVEMENT_SUMMARY_FILE,
    PhaseStatus,
    dependency_map,
    detect_mode,
    ensure_audit_dir,
    ensure_improvement_files,
    finalize,
    find_project_root,
    resolve_toolchain,
    utc_now_iso,
    write_text,
)


PLACEHOLDER_ARTIFACTS: Dict[str, str] = {
    "threat_model": str(AUDIT_DIR / "01_threat_model.md"),
    "static_analysis": str(AUDIT_DIR / "02_static_analysis.md"),
    "attack_vectors": str(AUDIT_DIR / "03_attack_vectors.md"),
    "proofs": str(AUDIT_DIR / "04_proofs.md"),
    "contest_context": str(AUDIT_DIR / "contest_context.json"),
    "privilege_map": str(AUDIT_DIR / "privilege_map.md"),
    "invariant_map": str(AUDIT_DIR / "invariant_map.md"),
    "rule_scan_json": str(AUDIT_DIR / "rule_scan.json"),
    "rule_scan_md": str(AUDIT_DIR / "rule_scan.md"),
    "exploit_rankings": str(AUDIT_DIR / "exploit_rankings.md"),
    "exploit_hypotheses": str(AUDIT_DIR / "exploit_hypotheses.md"),
    "proof_status": str(AUDIT_DIR / "proof_status.json"),
    "poc_spec": str(AUDIT_DIR / "poc_spec.md"),
    "severity_assessment": str(AUDIT_DIR / "severity_assessment.md"),
    "submission_notes": str(AUDIT_DIR / "submission_notes.md"),
    "flattened": str(AUDIT_DIR / "context_flattened.sol"),
    "topology": str(AUDIT_DIR / "topology_map.txt"),
    "external_calls": str(AUDIT_DIR / "external_calls.txt"),
    "storage_layout": str(AUDIT_DIR / "storage_layout.json"),
    "semantic_index": str(AUDIT_DIR / "semantic_index.json"),
    "action_catalog": str(AUDIT_DIR / "action_catalog.json"),
    "authority_graph": str(AUDIT_DIR / "authority_graph.json"),
    "dependency_graph": str(AUDIT_DIR / "dependency_graph.json"),
    "state_transition_map": str(AUDIT_DIR / "state_transition_map.json"),
    "invariant_candidates": str(AUDIT_DIR / "invariant_candidates.json"),
    "finding_candidates": str(AUDIT_DIR / "finding_candidates.json"),
    "finding_confirmations": str(AUDIT_DIR / "finding_confirmations.json"),
    "proof_plans": str(AUDIT_DIR / "proof_plans.json"),
    "repair_log": str(AUDIT_DIR / "repair_log.json"),
    "monitor_context": str(AUDIT_DIR / "skill_monitor_context.json"),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Initialize the Cerberus audit workspace.")
    parser.add_argument(
        "--target-dir",
        default=".",
        help="Directory containing the Solidity project. Defaults to the current directory.",
    )
    return parser.parse_args()


def create_placeholder_files() -> None:
    defaults = {
        PLACEHOLDER_ARTIFACTS["threat_model"]: "# Threat Model\n\n",
        PLACEHOLDER_ARTIFACTS["static_analysis"]: "# Static Analysis\n\n",
        PLACEHOLDER_ARTIFACTS["attack_vectors"]: "# Attack Vectors\n\n",
        PLACEHOLDER_ARTIFACTS["proofs"]: "# Proofs\n\n",
        PLACEHOLDER_ARTIFACTS["contest_context"]: "{}\n",
        PLACEHOLDER_ARTIFACTS["privilege_map"]: "# Privilege Map\n\n",
        PLACEHOLDER_ARTIFACTS["invariant_map"]: "# Invariant Map\n\n",
        PLACEHOLDER_ARTIFACTS["rule_scan_json"]: "{}\n",
        PLACEHOLDER_ARTIFACTS["rule_scan_md"]: "# Rule Scan\n\n",
        PLACEHOLDER_ARTIFACTS["exploit_rankings"]: "# Exploit Rankings\n\n",
        PLACEHOLDER_ARTIFACTS["exploit_hypotheses"]: "# Exploit Hypotheses\n\n",
        PLACEHOLDER_ARTIFACTS["proof_status"]: "{\n  \"findings\": []\n}\n",
        PLACEHOLDER_ARTIFACTS["poc_spec"]: "# PoC Spec\n\n",
        PLACEHOLDER_ARTIFACTS["severity_assessment"]: "# Severity Assessment\n\n",
        PLACEHOLDER_ARTIFACTS["submission_notes"]: "# Submission Notes\n\n",
        PLACEHOLDER_ARTIFACTS["flattened"]: "",
        PLACEHOLDER_ARTIFACTS["topology"]: "",
        PLACEHOLDER_ARTIFACTS["external_calls"]: "",
        PLACEHOLDER_ARTIFACTS["storage_layout"]: "{}\n",
        PLACEHOLDER_ARTIFACTS["semantic_index"]: "{\n  \"contracts\": [],\n  \"files\": []\n}\n",
        PLACEHOLDER_ARTIFACTS["action_catalog"]: "{\n  \"actions\": []\n}\n",
        PLACEHOLDER_ARTIFACTS["authority_graph"]: "{\n  \"roles\": [],\n  \"edges\": [],\n  \"sinks\": []\n}\n",
        PLACEHOLDER_ARTIFACTS["dependency_graph"]: "{\n  \"dependencies\": []\n}\n",
        PLACEHOLDER_ARTIFACTS["state_transition_map"]: "{\n  \"transitions\": []\n}\n",
        PLACEHOLDER_ARTIFACTS["invariant_candidates"]: "{\n  \"invariants\": []\n}\n",
        PLACEHOLDER_ARTIFACTS["finding_candidates"]: "{\n  \"findings\": []\n}\n",
        PLACEHOLDER_ARTIFACTS["finding_confirmations"]: "{\n  \"findings\": []\n}\n",
        PLACEHOLDER_ARTIFACTS["proof_plans"]: "{\n  \"proof_plans\": []\n}\n",
        PLACEHOLDER_ARTIFACTS["repair_log"]: "{\n  \"events\": []\n}\n",
    }
    for raw_path, content in defaults.items():
        path = Path(raw_path)
        # Preserve existing artifacts (e.g., pre-seeded benchmark fixtures)
        # Always skip if file already exists — init is rerunnable and must not clobber
        if not path.exists():
            write_text(path, content)


def main() -> int:
    args = parse_args()
    target_dir = Path(args.target_dir).resolve()
    warnings: List[str] = []
    errors: List[str] = []

    if not target_dir.exists() or not target_dir.is_dir():
        status = PhaseStatus(
            phase="init",
            ok=False,
            mode="degraded",
            artifacts=PLACEHOLDER_ARTIFACTS,
            warnings=warnings,
            errors=[f"Target directory does not exist or is not a directory: {target_dir}"],
            details={"target_dir": str(target_dir)},
        )
        return finalize(status)

    ensure_audit_dir()
    (AUDIT_DIR / "PoC").mkdir(parents=True, exist_ok=True)
    ensure_improvement_files()
    create_placeholder_files()

    deps = dependency_map("forge", "slither")
    for name, resolved_path in deps.items():
        if not resolved_path:
            warnings.append(f"{name} is not available; some phases will run in degraded mode.")

    project_root = find_project_root(target_dir)
    toolchain_config = resolve_toolchain(project_root)
    for name, resolved_path in toolchain_config.binaries.items():
        if not resolved_path and name not in deps:
            warnings.append(f"{name} is not available; some phases will run in degraded mode.")
    run_id = f"run-{utc_now_iso().replace(':', '-')}"
    import json as _json
    monitor_context = {
        "run_id": run_id,
        "persistent_log": str(IMPROVEMENT_LOG_FILE),
        "persistent_summary": str(IMPROVEMENT_SUMMARY_FILE),
        "hotspot_file": str(IMPROVEMENT_HOTSPOTS_FILE),
        "instruction": (
            "A monitoring subagent should review each phase output and append "
            "high-signal improvement observations."
        ),
    }
    write_text(
        Path(PLACEHOLDER_ARTIFACTS["monitor_context"]),
        _json.dumps(monitor_context, indent=2) + "\n",
    )
    status = PhaseStatus(
        phase="init",
        ok=True,
        mode=detect_mode(deps),
        artifacts=PLACEHOLDER_ARTIFACTS,
        warnings=warnings,
        errors=errors,
        details={
            "target_dir": str(target_dir),
            "project_root": str(project_root),
            "dependencies": deps,
            "run_id": run_id,
            "persistent_log": str(IMPROVEMENT_LOG_FILE),
            "persistent_summary": str(IMPROVEMENT_SUMMARY_FILE),
            "hotspot_file": str(IMPROVEMENT_HOTSPOTS_FILE),
            "toolchain_config": toolchain_config.to_dict(),
        },
    )
    return finalize(status)


if __name__ == "__main__":
    raise SystemExit(main())
