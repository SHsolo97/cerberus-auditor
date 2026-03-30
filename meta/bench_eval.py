from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Set, Tuple


SKILL_ROOT = Path(__file__).resolve().parent.parent
# benchmarks/ and resources/ both live under cerberus-proof-auditor/ (SKILL_ROOT)
BENCHMARKS_DIR = SKILL_ROOT / "benchmarks"
RESOURCES = SKILL_ROOT / "resources"

PIPELINE = [
    ("init", RESOURCES / "init_workspace.py"),
    ("preflight_or_repair", RESOURCES / "preflight_or_repair.py"),
    ("semantic_index", RESOURCES / "build_semantic_index.py"),
    ("ast_semantic_index", RESOURCES / "ast_semantic_index.py"),
    ("action_catalog", RESOURCES / "extract_actions.py"),
    ("authority_graph", RESOURCES / "build_authority_graph.py"),
    ("dependency_graph", RESOURCES / "build_dependency_graph.py"),
    ("invariant_candidates", RESOURCES / "mine_invariants.py"),
    ("finding_candidates", RESOURCES / "generate_finding_candidates.py"),
    ("finding_confirmation", RESOURCES / "confirm_findings.py"),
    ("proof_planning", RESOURCES / "plan_proofs.py"),
]

PHASE_SCRIPT_MAP = {phase_name: script for phase_name, script in PIPELINE}

# Phases that are allowed to fail in benchmarks (e.g. due to no invariant candidates)
ALLOW_FAILURE_PHASES = {"invariant_candidates", "ast_semantic_index"}


def run_json(cmd: List[str], cwd: Path, allow_failure: bool = False) -> Dict[str, object]:
    proc = subprocess.run(
        cmd,
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if proc.returncode != 0 and not allow_failure:
        raise AssertionError(
            "benchmark command failed\n"
            f"cmd: {' '.join(cmd)}\nstdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}"
        )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"command did not emit valid JSON: {' '.join(cmd)}\n{proc.stdout}") from exc
    if proc.returncode != 0 and allow_failure and payload.get("ok", True):
        raise AssertionError(f"command returned nonzero despite ok payload: {' '.join(cmd)}\n{proc.stdout}\n{proc.stderr}")
    return payload


def copy_fixture(src: Path, dst: Path) -> None:
    for item in src.iterdir():
        target = dst / item.name
        if item.is_dir():
            shutil.copytree(item, target)
        else:
            shutil.copy2(item, target)


def benchmark_dirs() -> List[Path]:
    if not BENCHMARKS_DIR.exists():
        return []
    return sorted(path for path in BENCHMARKS_DIR.iterdir() if path.is_dir())


def run_phase(phase_name: str, script: Path, workdir: Path, allow_failure: bool = False) -> Dict[str, object]:
    return run_json([sys.executable, str(script), "--target-dir", "src"], cwd=workdir, allow_failure=allow_failure)


def _load_expected_rejected(expected: Dict[str, object]) -> Set[str]:
    """Parse expected_rejected from the expected.json."""
    raw = expected.get("expected_rejected")
    if not isinstance(raw, list):
        return set()
    return {str(item) for item in raw if str(item).strip()}


def _confirmability_label_counts(proof_plans: List[Dict[str, object]]) -> Dict[str, int]:
    return {
        "confirmable_and_reproducible": sum(
            1 for p in proof_plans if p.get("confirmability") == "confirmable_and_reproducible"
        ),
        "confirmable_but_weak": sum(
            1 for p in proof_plans if p.get("confirmability") == "confirmable_but_weak"
        ),
        "interesting_but_unconfirmed": sum(
            1 for p in proof_plans if p.get("confirmability") == "interesting_but_unconfirmed"
        ),
    }


def run_single_benchmark(benchmark_dir: Path) -> Dict[str, object]:
    expected_path = benchmark_dir / "expected.json"
    expected = json.loads(expected_path.read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory(prefix=f"cerberus-bench-{benchmark_dir.name}-") as raw_tmp:
        workdir = Path(raw_tmp)
        copy_fixture(benchmark_dir, workdir)
        (workdir / "expected.json").unlink(missing_ok=True)

        preflight_script_sequence = expected.get("preflight_script_sequence", [])
        expected_preflight_decisions = [str(item) for item in expected.get("expected_preflight_decisions", []) if str(item).strip()]
        actual_preflight_decisions: List[str] = []
        corruption_steps = expected.get("corruption_steps", [])
        corruption_by_phase: Dict[str, List[Dict[str, object]]] = {}
        if isinstance(corruption_steps, list):
            for step in corruption_steps:
                if not isinstance(step, dict):
                    continue
                phase_name = str(step.get("before_phase", "")).strip()
                if not phase_name:
                    continue
                corruption_by_phase.setdefault(phase_name, []).append(step)
        actual_corruption_failures: List[str] = []

        for phase_name, script in PIPELINE:
            if phase_name == "init":
                payload = run_phase(phase_name, script, workdir)
            elif phase_name == "preflight_or_repair":
                script_sequence = preflight_script_sequence if isinstance(preflight_script_sequence, list) and preflight_script_sequence else ["__RESOURCE__"]
                payload = {}
                for script_entry in script_sequence:
                    script_ref = str(script_entry)
                    script_path = (
                        RESOURCES / "build_semantic_index.py"
                        if script_ref == "__RESOURCE__"
                        else (workdir / script_ref).resolve()
                    )
                    payload = run_json(
                        [
                            sys.executable,
                            str(script),
                            "--phase-name",
                            "semantic_index",
                            "--script-path",
                            str(script_path),
                            "--target-dir",
                            "src",
                        ],
                        cwd=workdir,
                        allow_failure=True,
                    )
                    actual_preflight_decisions.append(str(payload.get("details", {}).get("decision", "")))
                if expected_preflight_decisions and actual_preflight_decisions != expected_preflight_decisions:
                    raise AssertionError(
                        f"{benchmark_dir.name}: expected preflight decisions {expected_preflight_decisions}, "
                        f"got {actual_preflight_decisions}"
                    )
            else:
                for step in corruption_by_phase.get(phase_name, []):
                    artifact_path = workdir / str(step.get("write_path", ""))
                    artifact_path.parent.mkdir(parents=True, exist_ok=True)
                    artifact_path.write_text(str(step.get("content", "")), encoding="utf-8")
                    failure_payload = run_phase(phase_name, script, workdir, allow_failure=True)
                    if failure_payload.get("ok", True):
                        raise AssertionError(
                            f"{benchmark_dir.name}: expected phase {phase_name} to fail after artifact corruption."
                        )
                    actual_corruption_failures.append(phase_name)
                    for recovery_phase in step.get("recover_with_phases", []):
                        recovery_phase_name = str(recovery_phase)
                        recovery_script = PHASE_SCRIPT_MAP.get(recovery_phase_name)
                        if recovery_script is None:
                            raise AssertionError(f"{benchmark_dir.name}: unknown recovery phase {recovery_phase_name}")
                        recovery_payload = run_phase(recovery_phase_name, recovery_script, workdir)
                        if not recovery_payload.get("ok"):
                            raise AssertionError(
                                f"{benchmark_dir.name}: recovery phase {recovery_phase_name} did not succeed: {json.dumps(recovery_payload, indent=2)}"
                            )
                allow_fail = phase_name in ALLOW_FAILURE_PHASES
                payload = run_phase(phase_name, script, workdir, allow_failure=allow_fail)
            if phase_name == "preflight_or_repair":
                if expected_preflight_decisions:
                    if actual_preflight_decisions and actual_preflight_decisions[-1] != "resume":
                        raise AssertionError(f"{benchmark_dir.name}: preflight did not end in resume: {actual_preflight_decisions}")
                elif not payload.get("ok"):
                    raise AssertionError(f"{benchmark_dir.name}: phase {phase_name} did not succeed: {json.dumps(payload, indent=2)}")
            elif not payload.get("ok") and phase_name not in ALLOW_FAILURE_PHASES:
                raise AssertionError(f"{benchmark_dir.name}: phase {phase_name} did not succeed: {json.dumps(payload, indent=2)}")

        findings = json.loads((workdir / ".audit_board" / "finding_candidates.json").read_text(encoding="utf-8")).get("findings", [])
        confirmations = json.loads((workdir / ".audit_board" / "finding_confirmations.json").read_text(encoding="utf-8")).get("findings", [])
        proof_plans = json.loads((workdir / ".audit_board" / "proof_plans.json").read_text(encoding="utf-8")).get("proof_plans", [])

        finding_ids = {str(item.get("id", "")) for item in findings if isinstance(item, dict)}
        ordered_finding_ids = [str(item.get("id", "")) for item in findings if isinstance(item, dict)]
        confirmation_statuses = {
            str(item.get("candidate_id", "")): str(item.get("status", ""))
            for item in confirmations
            if isinstance(item, dict)
        }
        proof_plan_ids = {str(item.get("finding_id", "")) for item in proof_plans if isinstance(item, dict)}

        # ── Finding / confirmation checks ───────────────────────────────────────
        expected_findings = set(expected.get("expected_findings", []))
        expected_confirmed = set(expected.get("expected_confirmed", []))
        expected_rejected = _load_expected_rejected(expected)
        expected_proof_plans = set(expected.get("expected_proof_plans", []))
        forbidden_proof_plans = set(expected.get("forbidden_proof_plans", []))
        allowed_extra = set(expected.get("allowed_extra", []))
        expected_top_finding = str(expected.get("expected_top_finding", "")).strip()
        expected_order_prefix = [str(item) for item in expected.get("expected_order_prefix", []) if str(item).strip()]

        missing_findings = sorted(expected_findings - finding_ids)
        missing_confirmed = sorted(
            finding_id
            for finding_id in expected_confirmed
            if confirmation_statuses.get(finding_id) not in {"source_confirmed", "proof_ready"}
        )
        unexpected_extra = sorted(finding_id for finding_id in (finding_ids - expected_findings) if finding_id not in allowed_extra)
        missing_proof_plans = sorted(expected_proof_plans - proof_plan_ids)
        unexpected_proof_plans = sorted(proof_plan_id for proof_plan_id in proof_plan_ids if proof_plan_id in forbidden_proof_plans)

        # ── Rejected findings check ─────────────────────────────────────────────
        rejected_candidates = {
            str(item.get("candidate_id", ""))
            for item in confirmations
            if isinstance(item, dict) and item.get("status") == "rejected"
        }
        unexpected_rejected = sorted(rejected_candidates - expected_rejected - allowed_extra)
        missing_rejected = sorted(expected_rejected - rejected_candidates)

        actual_top_finding = ordered_finding_ids[0] if ordered_finding_ids else ""
        ranking_ok = not expected_top_finding or actual_top_finding == expected_top_finding
        order_prefix_ok = (
            not expected_order_prefix
            or ordered_finding_ids[: len(expected_order_prefix)] == expected_order_prefix
        )

        # ── Confirmability score checks ────────────────────────────────────────
        expected_confirmability = expected.get("expected_confirmability", {})
        actual_confirmability_counts = _confirmability_label_counts(proof_plans)
        confirmability_ok = (
            not expected_confirmability
            or (
                all(
                    actual_confirmability_counts.get(key, 0) == int(val)
                    for key, val in expected_confirmability.items()
                )
                and all(
                    actual_confirmability_counts.get(key, 0) == 0
                    for key in actual_confirmability_counts
                    if key not in expected_confirmability
                )
            )
        )
        confirmability_detail = (
            f"expected={expected_confirmability}, actual={actual_confirmability_counts}"
            if expected_confirmability
            else str(actual_confirmability_counts)
        )

        actual_corruption_failures = sorted(actual_corruption_failures)
        expected_corruption_failures = sorted(str(item) for item in expected.get("expected_corruption_failures", []))

        return {
            "benchmark": benchmark_dir.name,
            "expected_preflight_decisions": expected_preflight_decisions,
            "actual_preflight_decisions": actual_preflight_decisions,
            "expected_corruption_failures": expected_corruption_failures,
            "actual_corruption_failures": actual_corruption_failures,
            "allowed_extra": sorted(allowed_extra),
            "expected_findings": sorted(expected_findings),
            "expected_confirmed": sorted(expected_confirmed),
            "expected_rejected": sorted(expected_rejected),
            "expected_proof_plans": sorted(expected_proof_plans),
            "forbidden_proof_plans": sorted(forbidden_proof_plans),
            "expected_top_finding": expected_top_finding,
            "expected_order_prefix": expected_order_prefix,
            "found_findings": sorted(finding_ids),
            "ordered_findings": ordered_finding_ids,
            "actual_top_finding": actual_top_finding,
            "missing_findings": missing_findings,
            "missing_confirmed": missing_confirmed,
            "missing_rejected": missing_rejected,
            "unexpected_rejected": unexpected_rejected,
            "missing_proof_plans": missing_proof_plans,
            "unexpected_extra": unexpected_extra,
            "proof_plan_ids": sorted(proof_plan_ids),
            "unexpected_proof_plans": unexpected_proof_plans,
            "confirmability_detail": confirmability_detail,
            "confirmability_ok": confirmability_ok,
            "ranking_ok": ranking_ok,
            "order_prefix_ok": order_prefix_ok,
            "ok": (
                not missing_findings
                and not missing_confirmed
                and not missing_rejected
                and not unexpected_rejected
                and not missing_proof_plans
                and not unexpected_extra
                and not unexpected_proof_plans
                and ranking_ok
                and order_prefix_ok
                and confirmability_ok
                and actual_corruption_failures == expected_corruption_failures
            ),
        }


def summarize(results: List[Dict[str, object]]) -> Tuple[Dict[str, object], int]:
    total = len(results)
    passed = sum(1 for item in results if item.get("ok"))
    expected_total = sum(len(item.get("expected_findings", [])) for item in results)
    found_total = sum(
        len(item.get("expected_findings", [])) - len(item.get("missing_findings", []))
        for item in results
    )
    confirmed_total = sum(
        len(item.get("expected_confirmed", [])) - len(item.get("missing_confirmed", []))
        for item in results
    )
    expected_confirmed_total = sum(len(item.get("expected_confirmed", [])) for item in results)
    rejected_total = sum(
        len(item.get("expected_rejected", [])) - len(item.get("missing_rejected", []))
        for item in results
    )
    expected_rejected_total = sum(len(item.get("expected_rejected", [])) for item in results)
    summary = {
        "benchmark_count": total,
        "passed_count": passed,
        "candidate_recall": 1.0 if expected_total == 0 else round(found_total / expected_total, 4),
        "confirmed_recall": 1.0 if expected_confirmed_total == 0 else round(confirmed_total / expected_confirmed_total, 4),
        "rejected_recall": 1.0 if expected_rejected_total == 0 else round(rejected_total / expected_rejected_total, 4),
        "ranking_pass_rate": 1.0 if total == 0 else round(sum(1 for item in results if item.get("ranking_ok", True)) / total, 4),
        "order_prefix_pass_rate": 1.0 if total == 0 else round(sum(1 for item in results if item.get("order_prefix_ok", True)) / total, 4),
        "confirmability_pass_rate": 1.0 if total == 0 else round(sum(1 for item in results if item.get("confirmability_ok", True)) / total, 4),
        "results": results,
    }
    exit_code = 0 if passed == total else 1
    return summary, exit_code


def main() -> int:
    dirs = benchmark_dirs()
    if not dirs:
        print(json.dumps({"benchmark_count": 0, "passed_count": 0, "results": [], "warning": "No benchmarks found."}, indent=2))
        return 1

    results = [run_single_benchmark(path) for path in dirs]
    summary, exit_code = summarize(results)
    print(json.dumps(summary, indent=2, sort_keys=True))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
