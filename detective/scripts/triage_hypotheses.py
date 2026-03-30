from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List

from common import (
    AUDIT_DIR,
    STATUS_FILE,
    PhaseStatus,
    finalize,
    make_failure_status,
    read_json,
    read_text_file,
    write_text,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Promote raw audit signals into exploit hypotheses.")
    parser.add_argument(
        "--target-dir",
        default=".",
        help="Directory containing the Solidity project. Defaults to the current directory.",
    )
    return parser.parse_args()


def normalize_slug(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return slug or "finding"

def build_hypotheses() -> List[Dict[str, object]]:
    candidates_data = read_json(AUDIT_DIR / "finding_candidates.json")
    confirmations_data = read_json(AUDIT_DIR / "finding_confirmations.json")
    proof_plans_data = read_json(AUDIT_DIR / "proof_plans.json")

    candidates = candidates_data.get("findings") if isinstance(candidates_data, dict) else None
    confirmations = confirmations_data.get("findings") if isinstance(confirmations_data, dict) else None
    proof_plans = proof_plans_data.get("proof_plans") if isinstance(proof_plans_data, dict) else None

    if not isinstance(candidates, list):
        candidates = []
    if not isinstance(confirmations, list):
        confirmations = []
    if not isinstance(proof_plans, list):
        proof_plans = []

    confirmation_by_id = {
        str(item.get("candidate_id", "")): item for item in confirmations if isinstance(item, dict)
    }
    proof_by_id = {
        str(item.get("finding_id", "")): item for item in proof_plans if isinstance(item, dict)
    }

    hypotheses: List[Dict[str, object]] = []
    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        finding_id = str(candidate.get("id", ""))
        confirmation = confirmation_by_id.get(finding_id, {})
        proof_plan = proof_by_id.get(finding_id, {})
        status = str(confirmation.get("status", "weak_signal"))
        confidence = "high" if status in {"source_confirmed", "proof_ready"} else "medium" if candidate.get("confidence_score", 0) >= 0.5 else "low"
        hypotheses.append(
            {
                "id": finding_id,
                "title": candidate.get("title", "Untitled finding"),
                "signal": candidate.get("family", "not_determined"),
                "broken_invariant": candidate.get("violated_invariant", "Not determined"),
                "likely_severity": "medium" if status == "source_confirmed" else "not_determined",
                "likelihood": "medium" if status != "weak_signal" else "not_determined",
                "impact": candidate.get("violated_invariant", "not determined"),
                "required_assumptions": candidate.get("blocking_unknowns", []),
                "recommended_next_step": (
                    "Implement the structured proof plan."
                    if proof_plan
                    else "Resolve the remaining disqualifiers with source review."
                ),
                "evidence": candidate.get("evidence", []),
                "confidence": confidence,
                "status": status,
            }
        )

    if not hypotheses:
        hypotheses.append(
            {
                "id": "no-structured-hypothesis",
                "title": "No structured exploit hypothesis derived",
                "signal": "insufficient structured overlap",
                "broken_invariant": "Not determined",
                "likely_severity": "not_determined",
                "likelihood": "not_determined",
                "impact": "not determined",
                "required_assumptions": ["manual reasoning still required"],
                "recommended_next_step": "review the semantic artifacts and candidate generation rules manually",
                "evidence": [],
                "confidence": "low",
                "status": "hypothesis",
            }
        )
    return hypotheses


def render_markdown(hypotheses: List[Dict[str, object]]) -> str:
    lines = ["# Exploit Hypotheses", ""]
    for idx, item in enumerate(hypotheses, start=1):
        lines.append(f"## Hypothesis {idx} - {item['title']}")
        lines.append(f"- Signal: {item['signal']}")
        lines.append(f"- Confidence: {item['confidence']}")
        lines.append(f"- Broken invariant: {item['broken_invariant']}")
        lines.append(f"- Likely severity: {item['likely_severity']}")
        lines.append(f"- Likelihood hypothesis: {item['likelihood']}")
        lines.append(f"- Structured status: {item.get('status', 'hypothesis')}")
        lines.append(f"- Impact hypothesis: {item['impact']}")
        assumptions = item.get("required_assumptions", [])
        if assumptions:
            lines.append("- Minimum assumptions: " + "; ".join(str(x) for x in assumptions))
        evidence = item.get("evidence", [])
        if evidence:
            rendered = "; ".join(str(snippet) for snippet in evidence[:4])
            lines.append("- Evidence snippets: " + rendered)
        else:
            lines.append("- Evidence snippets: Not determined")
        lines.append(f"- Next deterministic step: {item['recommended_next_step']}")
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def build_proof_status(hypotheses: List[Dict[str, object]]) -> Dict[str, object]:
    findings: List[Dict[str, object]] = []
    for item in hypotheses:
        structured_status = str(item.get("status", "hypothesis"))
        proof_status = {
            "rejected": "hypothesis",
            "weak_signal": "hypothesis",
            "source_confirmed": "source_confirmed",
            "proof_ready": "deterministic_poc",
        }.get(structured_status, "hypothesis")
        findings.append(
            {
                "id": item.get("id") or normalize_slug(str(item["title"])),
                "title": item["title"],
                "status": proof_status,
                "confidence": item["confidence"],
                "likely_severity": item["likely_severity"],
                "likelihood": item["likelihood"],
                "impact_hypothesis": item["impact"],
                "broken_invariant": item["broken_invariant"],
                "recommended_next_step": item["recommended_next_step"],
            }
        )
    return {"findings": findings}


def main() -> int:
    args = parse_args()
    target_dir = Path(args.target_dir).resolve()
    warnings: List[str] = []

    if not target_dir.exists():
        status = make_failure_status(
            "hypothesis_triage",
            errors=[f"Target directory does not exist: {target_dir}"],
            warnings=warnings,
            details={"target_dir": str(target_dir)},
        )
        return finalize(status)

    status_snapshot = read_json(STATUS_FILE)
    init_details = status_snapshot.get("init", {}).get("details", {}) if isinstance(status_snapshot, dict) else {}
    run_id = init_details.get("run_id")

    hypotheses = build_hypotheses()
    markdown = render_markdown(hypotheses)
    proof_status = build_proof_status(hypotheses)

    write_text(AUDIT_DIR / "exploit_hypotheses.md", markdown)
    write_text(AUDIT_DIR / "proof_status.json", json.dumps(proof_status, indent=2) + "\n")

    if len(hypotheses) == 1 and hypotheses[0].get("confidence") == "low":
        warnings.append("Hypothesis triage ran with sparse structured artifacts; output may need heavier manual refinement.")

    status = PhaseStatus(
        phase="hypothesis_triage",
        ok=True,
        mode="full",
        artifacts={
            "exploit_hypotheses": str(AUDIT_DIR / "exploit_hypotheses.md"),
            "proof_status": str(AUDIT_DIR / "proof_status.json"),
        },
        warnings=warnings,
        errors=[],
        details={"target_dir": str(target_dir), "run_id": run_id, "hypothesis_count": len(hypotheses)},
    )
    return finalize(status)


if __name__ == "__main__":
    raise SystemExit(main())
