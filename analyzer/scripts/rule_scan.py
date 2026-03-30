from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Optional

from common import (
    AUDIT_DIR,
    STATUS_FILE,
    PhaseStatus,
    discover_solidity_files,
    file_has_concrete_contract,
    fatal_status,
    finalize,
    find_project_root,
    make_failure_status,
    read_json,
    read_text_file,
    strip_solidity_comments,
    write_text,
)


VALIDATIONS_PATH = Path(__file__).resolve().parent.parent.parent / "profiler" / "references" / "validations.md"
SHARP_EDGES_PATH = Path(__file__).resolve().parent.parent.parent / "profiler" / "references" / "sharp_edges.md"
SUPPRESSED_EXPLOIT_IDS = {
    "centralization-risks",
    "governance-flash-loan-attack",
    "front-running",
    "integer-overflow-underflow",
}
SEVERITY_ORDER = {"critical": 0, "high": 1, "error": 1, "medium": 2, "warning": 2, "low": 3, "info": 4}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run smart-contract validation rules and exploit heuristics.")
    parser.add_argument("--target-dir", required=True, help="Directory containing Solidity contracts.")
    return parser.parse_args()


def _parse_reference_sections(path: Path) -> List[str]:
    content = read_text_file(path)
    if not content:
        return []
    parts = re.split(r"^##\s+", content, flags=re.MULTILINE)
    return [part.strip() for part in parts if part.strip() and not part.strip().startswith("# ")]


def _extract_field(section: str, label: str) -> Optional[str]:
    pattern = rf"### \*\*{re.escape(label)}\*\*\s*\n(.+?)(?=\n### \*\*|\Z)"
    match = re.search(pattern, section, flags=re.DOTALL)
    if not match:
        return None
    return match.group(1).strip()


def parse_validations() -> List[Dict[str, object]]:
    rules: List[Dict[str, object]] = []
    for section in _parse_reference_sections(VALIDATIONS_PATH):
        rule_id = _extract_field(section, "Id")
        pattern = _extract_field(section, "Pattern")
        if not rule_id or not pattern:
            continue
        rules.append(
            {
                "id": rule_id,
                "description": _extract_field(section, "Description") or "",
                "pattern": pattern,
                "context_pattern": _extract_field(section, "Context Pattern"),
                "context_match": (_extract_field(section, "Context Match") or "").lower(),
                "message": _extract_field(section, "Message") or "",
                "severity": (_extract_field(section, "Severity") or "warning").lower(),
            }
        )
    return rules


def parse_sharp_edges() -> List[Dict[str, object]]:
    edges: List[Dict[str, object]] = []
    for section in _parse_reference_sections(SHARP_EDGES_PATH):
        edge_id = _extract_field(section, "Id")
        pattern = _extract_field(section, "Detection Pattern")
        if not edge_id or not pattern:
            continue
        edges.append(
            {
                "id": edge_id,
                "severity": (_extract_field(section, "Severity") or "warning").lower(),
                "description": _extract_field(section, "Description") or "",
                "pattern": pattern,
                "symptoms": _extract_field(section, "Symptoms") or "",
            }
        )
    return edges


def safe_regex(pattern: str) -> Optional[re.Pattern[str]]:
    try:
        return re.compile(pattern, flags=re.MULTILINE | re.DOTALL)
    except re.error:
        return None


def scan_rule(rule: Dict[str, object], path: Path, content: str) -> Optional[Dict[str, object]]:
    pattern = safe_regex(str(rule["pattern"]))
    if pattern is None:
        return None
    matches = list(pattern.finditer(content))
    if not matches:
        return None

    context_pattern_raw = rule.get("context_pattern")
    context_expectation = str(rule.get("context_match") or "")
    if context_pattern_raw:
        context_pattern = safe_regex(str(context_pattern_raw))
        if context_pattern is not None:
            context_found = bool(context_pattern.search(content))
            if context_expectation == "absent" and context_found:
                return None
            if context_expectation == "present" and not context_found:
                return None

    sample = matches[0].group(0).strip().replace("\n", " ")
    if len(sample) > 180:
        sample = sample[:177] + "..."
    return {
        "rule_id": rule["id"],
        "severity": rule["severity"],
        "message": rule["message"],
        "path": str(path),
        "match_count": len(matches),
        "sample": sample,
    }


def _evidence_map(findings: List[Dict[str, object]]) -> Dict[str, List[str]]:
    evidence: Dict[str, List[str]] = {}

    for item in findings:
        path = str(item.get("path", "")).strip()
        if path:
            evidence.setdefault(path, []).append(f"rule:{item.get('rule_id', 'unknown')}")

    for artifact_name, prefix in (("privilege_map.md", "privilege"), ("invariant_map.md", "invariant")):
        artifact = AUDIT_DIR / artifact_name
        if not artifact.exists():
            continue
        for line in artifact.read_text(encoding="utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if not stripped.startswith("- "):
                continue
            entry = stripped[2:]
            match = re.search(r"\b([A-Za-z0-9_./-]+\.sol)\b", entry)
            if match:
                evidence.setdefault(match.group(1), []).append(prefix)

    return evidence


def score_exploit_family(
    edge: Dict[str, object],
    path: Path,
    content: str,
    *,
    evidence_tokens: List[str],
) -> Optional[Dict[str, object]]:
    pattern = safe_regex(str(edge["pattern"]))
    if pattern is None:
        return None
    matches = list(pattern.finditer(content))
    if not matches:
        return None
    if not evidence_tokens:
        return None
    score = min(len(matches), 5)
    confidence = min(score + len(set(evidence_tokens)), 8)
    return {
        "id": edge["id"],
        "severity": edge["severity"],
        "description": edge["description"],
        "path": str(path),
        "score": score,
        "confidence": confidence,
        "evidence_count": len(matches),
        "evidence_tokens": sorted(set(evidence_tokens)),
    }


def render_rule_scan_md(findings: List[Dict[str, object]]) -> str:
    lines: List[str] = ["# Rule Scan", ""]
    if not findings:
        lines.append("No native validation hits were extracted from the configured rules.")
        lines.append("")
        return "\n".join(lines)

    grouped: Dict[str, List[Dict[str, object]]] = {}
    for finding in findings:
        grouped.setdefault(str(finding["severity"]), []).append(finding)

    for severity in ("error", "warning", "info"):
        items = grouped.get(severity, [])
        if not items:
            continue
        lines.append(f"## {severity.title()}")
        for item in items:
            lines.append(
                f"- `{item['rule_id']}` in `{item['path']}` x{item['match_count']}: {item['message']}"
            )
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def render_exploit_rankings_md(rankings: List[Dict[str, object]]) -> str:
    lines: List[str] = ["# Exploit Rankings", ""]
    if not rankings:
        lines.append("No exploit-family heuristics matched the configured sharp-edge patterns.")
        lines.append("")
        return "\n".join(lines)

    lines.append("## Likely Applicable Families")
    for item in rankings:
        lines.append(
            f"- `{item['id']}` on `{item['path']}` score={item['score']} confidence={item['confidence']} severity={item['severity']} evidence={','.join(item['evidence_tokens'])}: {item['description']}"
        )
    lines.append("")
    return "\n".join(lines)


def load_scope_filter(project_root: Path) -> Optional[set[str]]:
    contest_context = read_json(AUDIT_DIR / "contest_context.json")
    scope_files = contest_context.get("scope_files") if isinstance(contest_context, dict) else None
    if not isinstance(scope_files, list) or not scope_files:
        return None
    normalized: set[str] = set()
    for raw in scope_files:
        if not isinstance(raw, str):
            continue
        cleaned = raw.strip().lstrip("./")
        if cleaned.endswith(".sol"):
            normalized.add(cleaned)
    return normalized or None


def main() -> int:
    args = parse_args()
    target_dir = Path(args.target_dir).resolve()
    warnings: List[str] = []
    errors: List[str] = []
    artifacts = {
        "rule_scan_json": str(AUDIT_DIR / "rule_scan.json"),
        "rule_scan_md": str(AUDIT_DIR / "rule_scan.md"),
        "exploit_rankings": str(AUDIT_DIR / "exploit_rankings.md"),
    }

    try:
        if not target_dir.exists() or not target_dir.is_dir():
            status = make_failure_status(
                "rule_scan",
                errors=[f"Target directory does not exist or is not a directory: {target_dir}"],
                warnings=warnings,
                artifacts=artifacts,
                details={"target_dir": str(target_dir)},
            )
            return finalize(status)

        files = discover_solidity_files(target_dir)
        if not files:
            status = make_failure_status(
                "rule_scan",
                errors=[f"No Solidity files found under: {target_dir}"],
                warnings=warnings,
                artifacts=artifacts,
                details={"target_dir": str(target_dir)},
            )
            return finalize(status)

        project_root = find_project_root(target_dir)
        scope_filter = load_scope_filter(project_root)
        validations = parse_validations()
        sharp_edges = parse_sharp_edges()
        if not validations:
            warnings.append("No validation rules could be parsed from profiler/references/validations.md.")
        if not sharp_edges:
            warnings.append("No sharp-edge heuristics could be parsed from profiler/references/sharp_edges.md.")

        findings: List[Dict[str, object]] = []
        for path in files:
            content = read_text_file(path)
            if not content:
                continue
            rel_path = path.relative_to(project_root).as_posix()
            if scope_filter is not None and rel_path not in scope_filter:
                continue
            rel_obj = Path(rel_path)
            code_only = strip_solidity_comments(content)
            for rule in validations:
                finding = scan_rule(rule, rel_obj, code_only)
                if finding:
                    findings.append(finding)

        evidence_map = _evidence_map(findings)
        exploit_rankings: List[Dict[str, object]] = []
        for path in files:
            content = read_text_file(path)
            if not content:
                continue
            rel_path = path.relative_to(project_root).as_posix()
            if scope_filter is not None and rel_path not in scope_filter:
                continue
            rel_obj = Path(rel_path)
            if not file_has_concrete_contract(path):
                continue
            code_only = strip_solidity_comments(content)
            evidence_tokens = list(evidence_map.get(rel_path, []))
            evidence_tokens.append("concrete-contract")
            for edge in sharp_edges:
                if str(edge.get("id")) in SUPPRESSED_EXPLOIT_IDS:
                    continue
                ranking = score_exploit_family(edge, rel_obj, code_only, evidence_tokens=evidence_tokens)
                if ranking:
                    exploit_rankings.append(ranking)

        exploit_rankings.sort(
            key=lambda item: (
                SEVERITY_ORDER.get(str(item["severity"]), 99),
                -int(item["confidence"]),
                -int(item["score"]),
                str(item["id"]),
                str(item["path"]),
            )
        )
        findings.sort(
            key=lambda item: (
                SEVERITY_ORDER.get(str(item["severity"]), 99),
                str(item["rule_id"]),
                str(item["path"]),
            )
        )

        write_text(
            Path(artifacts["rule_scan_json"]),
            json.dumps(
                {
                    "findings": findings,
                    "rule_count": len(validations),
                "scanned_file_count": len(files),
                    "scope_filter_active": bool(scope_filter),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
        )
        write_text(Path(artifacts["rule_scan_md"]), render_rule_scan_md(findings))
        write_text(Path(artifacts["exploit_rankings"]), render_exploit_rankings_md(exploit_rankings[:20]))

        status_snapshot = read_json(STATUS_FILE)
        init_details = status_snapshot.get("init", {}).get("details", {}) if isinstance(status_snapshot, dict) else {}
        run_id = init_details.get("run_id")
        status = PhaseStatus(
            phase="rule_scan",
            ok=True,
            mode="full",
            artifacts=artifacts,
            warnings=warnings,
            errors=errors,
            details={
                "target_dir": str(target_dir),
                "project_root": str(find_project_root(target_dir)),
                "parsed_rules": len(validations),
                "parsed_sharp_edges": len(sharp_edges),
                "finding_count": len(findings),
                "exploit_ranking_count": len(exploit_rankings),
                "run_id": run_id,
            },
        )
        return finalize(status)
    except Exception as exc:
        status = fatal_status(
            "rule_scan",
            exc,
            warnings=warnings,
            artifacts=artifacts,
            details={"target_dir": str(target_dir)},
        )
        return finalize(status, exit_code=1)


if __name__ == "__main__":
    raise SystemExit(main())
