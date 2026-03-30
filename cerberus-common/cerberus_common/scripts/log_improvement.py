from __future__ import annotations

import argparse
from typing import List

from common import (
    IMPROVEMENT_HOTSPOTS_FILE,
    IMPROVEMENT_LOG_FILE,
    IMPROVEMENT_SUMMARY_FILE,
    append_improvement_entry,
    utc_now_iso,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Append a structured skill-improvement observation.")
    parser.add_argument("--run-id", required=True, help="Run identifier from .audit_board/skill_monitor_context.json.")
    parser.add_argument("--phase", required=True, help="Skill phase associated with the observation.")
    parser.add_argument("--severity", choices=("low", "medium", "high"), required=True, help="Operational importance.")
    parser.add_argument("--category", required=True, help="Short machine-friendly category, e.g. output_quality.")
    parser.add_argument("--summary", required=True, help="One-line problem statement.")
    parser.add_argument("--suggested-fix", required=True, help="Concrete improvement to implement later.")
    parser.add_argument("--source", default="monitor_subagent", help="Who recorded the observation.")
    parser.add_argument("--evidence", action="append", default=[], help="Artifact path or note supporting the observation.")
    parser.add_argument("--detail", action="append", default=[], help="Extra free-form details.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()

    if not args.summary.strip():
        raise SystemExit("--summary must not be empty")

    details: List[str] = [item.strip() for item in args.detail if item.strip()]
    evidence: List[str] = [item.strip() for item in args.evidence if item.strip()]

    append_improvement_entry(
        {
            "timestamp": utc_now_iso(),
            "run_id": args.run_id,
            "phase": args.phase,
            "severity": args.severity,
            "category": args.category,
            "source": args.source,
            "summary": args.summary,
            "details": details,
            "evidence": evidence,
            "suggested_fix": args.suggested_fix,
        }
    )

    import json as _json
    print(
        _json.dumps(
            {
                "ok": True,
                "log_file": str(IMPROVEMENT_LOG_FILE),
                "summary_file": str(IMPROVEMENT_SUMMARY_FILE),
                "hotspots_file": str(IMPROVEMENT_HOTSPOTS_FILE),
                "run_id": args.run_id,
                "phase": args.phase,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
