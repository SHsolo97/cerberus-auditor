from __future__ import annotations

import argparse
import shutil
from pathlib import Path
from typing import Dict, List

from common import AUDIT_DIR, STATUS_FILE, PhaseStatus, finalize, get_audit_dir, make_failure_status, read_json, set_audit_dir, write_text


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a contest-ready submission bundle for a finding.")
    parser.add_argument(
        "--target-dir",
        default=".",
        help="Directory containing the Solidity project. Defaults to CWD.",
    )
    parser.add_argument("--finding-id", required=True, help="Stable slug for the finding, e.g. trusted-filler-lockup.")
    parser.add_argument("--title", required=True, help="User-facing finding title.")
    parser.add_argument("--severity", required=True, help="Proposed severity label.")
    parser.add_argument(
        "--template",
        required=True,
        choices=("minimal_with_poc", "detailed_with_instructions", "severity_argument_only"),
        help="Submission template style.",
    )
    parser.add_argument("--poc-path", required=True, help="Path to the PoC file to include or reference.")
    parser.add_argument(
        "--bundle-dir",
        default=str(AUDIT_DIR / "PoC" / "final_submission"),
        help="Output directory for the final submission bundle.",
    )
    return parser.parse_args()


def report_template(title: str, severity: str, template: str, poc_name: str) -> str:
    lines = [
        "## Title",
        "",
        title,
        "",
        "## Severity",
        "",
        severity,
        "",
        "## Description",
        "",
    ]
    if template == "minimal_with_poc":
        lines.extend(
            [
                "Lead with the broken invariant, the minimum assumptions required, and the measurable impact in 2-4 short paragraphs.",
                "Prefer protocol-owned impact and concrete final state over implementation detail.",
                "",
                "## Proof of Concept",
                "",
                f"Runnable PoC: `{poc_name}`",
                "",
                "List only the steps the PoC proves and the final assertion that demonstrates impact.",
                "",
                "## Recommendation",
                "",
                "State the minimum safe design change that removes the hard dependency or stale authority.",
            ]
        )
    elif template == "detailed_with_instructions":
        lines.extend(
            [
                "Provide root cause, impact framing, and why the issue is valid even if severity-capped.",
                "",
                "## Reproduction",
                "",
                f"Runnable PoC: `{poc_name}`",
                "",
                "List the exact steps and expected revert or final state.",
                "",
                "## Recommendation",
                "",
                "Describe the explicit governance, recovery, or rotation path that should exist.",
            ]
        )
    else:
        lines.extend(
            [
                "Explain why the issue is valid and how it should be severity-scored.",
                "",
                "## Supporting Proof",
                "",
                f"PoC or evidence file: `{poc_name}`",
            ]
        )
    return "\n".join(lines).rstrip() + "\n"


def update_manifest(manifest_path: Path, entries: List[Dict[str, str]]) -> None:
    lines = ["# Final Submission Bundle", ""]
    for item in entries:
        lines.append(f"## {item['id']}")
        lines.append(f"- Title: {item['title']}")
        lines.append(f"- Severity: {item['severity']}")
        lines.append(f"- Template: {item['template']}")
        lines.append(f"- Report: {item['report']}")
        lines.append(f"- PoC: {item['poc']}")
        if item.get("template") == "minimal_with_poc":
            lines.append("- Bundle note: optimized for fast judging with a deterministic runnable proof.")
        elif item.get("template") == "detailed_with_instructions":
            lines.append("- Bundle note: optimized for lower-severity or recovery-path findings that need clearer validity framing.")
        lines.append("")
    write_text(manifest_path, "\n".join(lines).rstrip() + "\n")


def main() -> int:
    # Pre-parse just --target-dir so set_audit_dir is called before the full
    # parse (whose --bundle-dir default depends on get_audit_dir())
    _pre = argparse.ArgumentParser(add_help=False)
    _pre.add_argument("--target-dir", default=".")
    _ns, _ = _pre.parse_known_args()
    set_audit_dir(Path(_ns.target_dir))

    args = parse_args()
    status_snapshot = read_json(STATUS_FILE)
    init_details = status_snapshot.get("init", {}).get("details", {}) if isinstance(status_snapshot, dict) else {}
    run_id = init_details.get("run_id")

    poc_source = Path(args.poc_path)
    if not poc_source.exists():
        status = make_failure_status(
            "submission_bundle",
            errors=[f"PoC path does not exist: {poc_source}"],
            details={"run_id": run_id, "poc_path": args.poc_path},
        )
        return finalize(status)

    bundle_dir = Path(args.bundle_dir)
    bundle_dir.mkdir(parents=True, exist_ok=True)

    safe_slug = args.finding_id.strip().replace(" ", "-")
    report_name = f"{safe_slug}.md"
    copied_poc_name = f"{safe_slug}{poc_source.suffix}"
    report_path = bundle_dir / report_name
    copied_poc_path = bundle_dir / copied_poc_name
    manifest_path = bundle_dir / "MANIFEST.md"

    if poc_source.resolve() != copied_poc_path.resolve():
        shutil.copy2(poc_source, copied_poc_path)

    write_text(report_path, report_template(args.title, args.severity, args.template, copied_poc_name))

    existing_entries: List[Dict[str, str]] = []
    manifest_content = manifest_path.read_text(encoding="utf-8") if manifest_path.exists() else ""
    for block in manifest_content.split("## "):
        block = block.strip()
        if not block:
            continue
        lines = [line.strip() for line in block.splitlines() if line.strip()]
        if not lines:
            continue
        entry: Dict[str, str] = {"id": lines[0]}
        for line in lines[1:]:
            if ":" not in line:
                continue
            key, value = line[2:].split(":", 1) if line.startswith("- ") else line.split(":", 1)
            entry[key.strip().lower()] = value.strip()
        existing_entries.append(entry)

    new_entry = {
        "id": safe_slug,
        "title": args.title,
        "severity": args.severity,
        "template": args.template,
        "report": report_name,
        "poc": copied_poc_name,
    }
    existing_entries = [entry for entry in existing_entries if entry.get("id") != safe_slug]
    existing_entries.append(new_entry)
    existing_entries.sort(key=lambda item: item["id"])
    update_manifest(manifest_path, existing_entries)

    status = PhaseStatus(
        phase="submission_bundle",
        ok=True,
        mode="full",
        artifacts={
            "bundle_dir": str(bundle_dir),
            "manifest": str(manifest_path),
            "report": str(report_path),
            "poc": str(copied_poc_path),
        },
        warnings=[],
        errors=[],
        details={
            "run_id": run_id,
            "finding_id": safe_slug,
            "severity": args.severity,
            "template": args.template,
        },
    )
    return finalize(status)


if __name__ == "__main__":
    raise SystemExit(main())
