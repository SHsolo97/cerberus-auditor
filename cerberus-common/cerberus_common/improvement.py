"""
cerberus_common.improvement — Improvement hot-spot tracking loop.

Provides structured append, resolution, and aggregation of recurring skill issues.
Registers auto_log_status_observations with io.py at import time to avoid
a circular dependency between io.py and improvement.py.
"""
from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from hashlib import sha1
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional

from . import types as _t
from . import toolchain as _tc
from . import io as _io

# ── Auto-register with io.py ───────────────────────────────────────────────────

_auto_log_impl: Optional[Callable[..., None]] = None


def _create_auto_log_fn() -> Callable[[_t.PhaseStatus], None]:
    """Returns the auto-log function bound to THIS module's paths."""
    def auto_log(status: _t.PhaseStatus, *, run_id: Optional[str] = None) -> None:
        if not status.warnings and not status.errors:
            return

        def should_skip(message: str) -> bool:
            lowered = message.lower()
            return (
                ("not available" in lowered)
                or ("captured as raw text" in lowered)
                or lowered.startswith("storage layout unavailable for ")
            )

        normalized_run_id = run_id or "unknown"

        for message in status.errors:
            if should_skip(message):
                continue
            if _improvement_entry_exists(run_id=normalized_run_id, phase=status.phase, summary=message):
                continue
            append_improvement_entry(
                {
                    "timestamp": utc_now_iso(),
                    "run_id": normalized_run_id,
                    "phase": status.phase,
                    "severity": "high",
                    "category": "runtime_error",
                    "source": "automatic_status_logger",
                    "summary": message,
                    "details": {
                        "mode": status.mode,
                        "artifacts": status.artifacts,
                    },
                    "suggested_fix": "Inspect the failing phase and update the skill to prevent this recurring error.",
                }
            )

        for message in status.warnings:
            if should_skip(message):
                continue
            if _improvement_entry_exists(run_id=normalized_run_id, phase=status.phase, summary=message):
                continue
            append_improvement_entry(
                {
                    "timestamp": utc_now_iso(),
                    "run_id": normalized_run_id,
                    "phase": status.phase,
                    "severity": "medium",
                    "category": "runtime_warning",
                    "source": "automatic_status_logger",
                    "summary": message,
                    "details": {
                        "mode": status.mode,
                        "artifacts": status.artifacts,
                    },
                    "suggested_fix": "Review whether the warning indicates a recurring weakness in the skill workflow.",
                }
            )

    return auto_log


# Register once when this module is first imported
_auto_log_impl = _create_auto_log_fn()
_io.register_auto_log_fn(_auto_log_impl)


# ── Entry point for io.py ──────────────────────────────────────────────────────

def auto_log_status_observations(status: _t.PhaseStatus, *, run_id: Optional[str] = None) -> None:
    """Called by io.finalize(). Uses paths resolved via toolchain.py."""
    if _auto_log_impl is not None:
        _auto_log_impl(status, run_id=run_id)


# ── Utilities ───────────────────────────────────────────────────────────────────

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _normalize_improvement_summary(summary: str) -> str:
    return " ".join(summary.strip().split())


def _entry_fingerprint(entry: Mapping[str, Any]) -> str:
    category = str(entry.get("category", "")).strip().lower()
    summary = _normalize_improvement_summary(str(entry.get("summary", ""))).lower()
    suggested_fix = " ".join(str(entry.get("suggested_fix", "")).strip().split()).lower()
    return sha1(f"{category}|{summary}|{suggested_fix}".encode("utf-8")).hexdigest()[:16]


def _improvement_entry_exists(*, run_id: str, phase: str, summary: str) -> bool:
    log_file = _tc.IMPROVEMENT_LOG_FILE()
    if not log_file.exists():
        return False
    try:
        lines = log_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    for line in lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if (
            isinstance(entry, dict)
            and entry.get("run_id") == run_id
            and entry.get("phase") == phase
            and entry.get("summary") == summary
        ):
            return True
    return False


# ── Core functions ─────────────────────────────────────────────────────────────

def ensure_improvement_files() -> None:
    """Ensures all improvement tracking files exist."""
    meta_dir = _tc.META_DIR()
    meta_dir.mkdir(parents=True, exist_ok=True)
    log_file = _tc.IMPROVEMENT_LOG_FILE()
    summary_file = _tc.IMPROVEMENT_SUMMARY_FILE()
    hotspots_file = _tc.IMPROVEMENT_HOTSPOTS_FILE()
    resolved_file = _tc.RESOLVED_HOTSPOTS_FILE()

    if not log_file.exists():
        log_file.write_text("", encoding="utf-8")
    if not summary_file.exists():
        summary_file.write_text(
            "# Skill Improvement Summary\n\n"
            "Auto-generated summary of recurring improvement opportunities.\n",
            encoding="utf-8",
        )
    if not hotspots_file.exists():
        hotspots_file.write_text("{\"hotspots\": []}\n", encoding="utf-8")
    if not resolved_file.exists():
        resolved_file.write_text("{\"resolved\": []}\n", encoding="utf-8")


def append_improvement_entry(entry: Mapping[str, Any]) -> None:
    """Atomically append an entry to the improvement log."""
    ensure_improvement_files()
    log_file = _tc.IMPROVEMENT_LOG_FILE()
    line = json.dumps(dict(entry), sort_keys=True) + "\n"
    try:
        fd, tmp_path_str = tempfile.mkstemp(
            dir=log_file.parent,
            prefix=".improvement_log_tmp_",
            suffix=".jsonl",
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as tmp_handle:
                existing = log_file.read_text(encoding="utf-8") if log_file.exists() else ""
                tmp_handle.write(existing)
                tmp_handle.write(line)
                tmp_handle.flush()
                os.fsync(tmp_handle.fileno())
        except Exception:
            os.unlink(tmp_path_str)
            raise
        os.replace(tmp_path_str, log_file)
    except OSError:
        with log_file.open("a", encoding="utf-8") as handle:
            handle.write(line)
    refresh_improvement_artifacts()


def read_resolved_hotspots() -> Dict[str, Dict[str, Any]]:
    resolved_file = _tc.RESOLVED_HOTSPOTS_FILE()
    data = _t.read_json(resolved_file)
    rows = data.get("resolved", []) if isinstance(data, dict) else []
    resolved: Dict[str, Dict[str, Any]] = {}
    if not isinstance(rows, list):
        return resolved
    for row in rows:
        if not isinstance(row, dict):
            continue
        fingerprint = str(row.get("fingerprint", "")).strip()
        if fingerprint:
            resolved[fingerprint] = row
    return resolved


def write_resolved_hotspots(rows: List[Dict[str, Any]]) -> None:
    ensure_improvement_files()
    resolved_file = _tc.RESOLVED_HOTSPOTS_FILE()
    resolved_file.write_text(json.dumps({"resolved": rows}, indent=2) + "\n", encoding="utf-8")


def resolve_hotspot(
    *,
    fingerprint: str,
    resolution_note: str,
    resolved_by: str,
    resolved_in_run_id: Optional[str] = None,
    summary: Optional[str] = None,
) -> None:
    resolved = read_resolved_hotspots()
    resolved[fingerprint] = {
        "fingerprint": fingerprint,
        "summary": summary or resolved.get(fingerprint, {}).get("summary", ""),
        "resolution_note": resolution_note.strip(),
        "resolved_by": resolved_by.strip(),
        "resolved_in_run_id": resolved_in_run_id or "",
        "resolved_at": utc_now_iso(),
    }
    rows = sorted(resolved.values(), key=lambda row: (row.get("resolved_at", ""), row.get("fingerprint", "")))
    write_resolved_hotspots(rows)
    refresh_improvement_artifacts()


def reopen_hotspot(*, fingerprint: str) -> None:
    resolved = read_resolved_hotspots()
    if fingerprint in resolved:
        del resolved[fingerprint]
        rows = sorted(resolved.values(), key=lambda row: (row.get("resolved_at", ""), row.get("fingerprint", "")))
        write_resolved_hotspots(rows)
    refresh_improvement_artifacts()


def _should_ignore_for_summary(entry: Mapping[str, Any]) -> bool:
    summary = str(entry.get("summary", "")).lower()
    source = str(entry.get("source", ""))
    details = str(entry.get("details", "")).lower()
    return (
        "not available" in summary
        or "captured as raw text" in summary
        or summary.startswith("storage layout unavailable for ")
        or (source == "automatic_status_logger" and "degraded" in details)
    )


def _severity_rank(severity: str) -> int:
    return {"low": 1, "medium": 2, "high": 3}.get(severity, 0)


def refresh_improvement_artifacts() -> None:
    """Reaggregate the improvement log into hotspots.json and skill_improvements.md."""
    ensure_improvement_files()
    log_file = _tc.IMPROVEMENT_LOG_FILE()
    hotspots_file = _tc.IMPROVEMENT_HOTSPOTS_FILE()
    summary_file = _tc.IMPROVEMENT_SUMMARY_FILE()

    try:
        lines = log_file.read_text(encoding="utf-8").splitlines()
    except OSError:
        lines = []

    resolved = read_resolved_hotspots()
    groups: Dict[str, Dict[str, Any]] = {}
    considered_entries = 0

    for line in lines:
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(entry, dict):
            continue
        if _should_ignore_for_summary(entry):
            continue

        considered_entries += 1
        fingerprint = _entry_fingerprint(entry)
        group = groups.get(fingerprint)
        if group is None:
            group = {
                "fingerprint": fingerprint,
                "summary": _normalize_improvement_summary(str(entry.get("summary", ""))),
                "category": str(entry.get("category", "")),
                "suggested_fix": str(entry.get("suggested_fix", "")),
                "severity": str(entry.get("severity", "low")),
                "count": 0,
                "run_ids": set(),
                "phases": set(),
                "sources": set(),
                "last_seen": "",
            }
            groups[fingerprint] = group

        group["count"] += 1
        group["run_ids"].add(str(entry.get("run_id", "unknown")))
        group["phases"].add(str(entry.get("phase", "unknown")))
        group["sources"].add(str(entry.get("source", "unknown")))
        timestamp = str(entry.get("timestamp", ""))
        if timestamp > str(group["last_seen"]):
            group["last_seen"] = timestamp
        if _severity_rank(str(entry.get("severity", "low"))) > _severity_rank(str(group["severity"])):
            group["severity"] = str(entry.get("severity", "low"))

    hotspots: List[Dict[str, Any]] = []
    for group in groups.values():
        priority = (_severity_rank(group["severity"]) * 100) + min(int(group["count"]), 10) * 10
        if "monitor_subagent" in group["sources"]:
            priority += 15
        hotspots.append(
            {
                "fingerprint": group["fingerprint"],
                "summary": group["summary"],
                "category": group["category"],
                "suggested_fix": group["suggested_fix"],
                "severity": group["severity"],
                "count": group["count"],
                "run_count": len(group["run_ids"]),
                "phases": sorted(group["phases"]),
                "sources": sorted(group["sources"]),
                "last_seen": group["last_seen"],
                "priority": priority,
            }
        )

    hotspots.sort(key=lambda item: (-int(item["priority"]), -int(item["count"]), item["summary"]))
    active_hotspots = [item for item in hotspots if item["fingerprint"] not in resolved]
    resolved_hotspots = []
    for item in hotspots:
        if item["fingerprint"] in resolved:
            merged = dict(item)
            merged["resolution"] = resolved[item["fingerprint"]]
            resolved_hotspots.append(merged)

    hotspots_file.write_text(
        json.dumps({"hotspots": active_hotspots[:20], "resolved": resolved_hotspots[:20]}, indent=2) + "\n",
        encoding="utf-8",
    )

    lines_out = [
        "# Skill Improvement Summary",
        "",
        "Auto-generated summary of recurring improvement opportunities.",
        "",
        f"- Considered entries: {considered_entries}",
        f"- Active hotspots: {len(active_hotspots)}",
        f"- Resolved hotspots: {len(resolved_hotspots)}",
        "",
        "## Top Hotspots",
        "",
    ]
    if not active_hotspots:
        lines_out.append("- No active high-signal hotspots recorded.")
    else:
        for item in active_hotspots[:10]:
            lines_out.append(
                f"- [{item['severity']}] x{item['count']} across {item['run_count']} run(s): {item['summary']}"
            )
            lines_out.append(f"  Fix: {item['suggested_fix']}")
            lines_out.append(
                f"  Phase(s): {', '.join(item['phases'])} | Source(s): {', '.join(item['sources'])} | Last seen: {item['last_seen']}"
            )
    lines_out.extend(
        [
            "",
            "## Resolved Hotspots",
            "",
        ]
    )
    if not resolved_hotspots:
        lines_out.append("- No resolved hotspots recorded.")
    else:
        for item in resolved_hotspots[:10]:
            resolution = item["resolution"]
            lines_out.append(f"- {item['summary']}")
            lines_out.append(
                f"  Resolved by {resolution.get('resolved_by', 'unknown')} at {resolution.get('resolved_at', '')}: {resolution.get('resolution_note', '')}"
            )
    lines_out.extend(
        [
            "",
            "## Fast Loop",
            "",
            "- Before using the skill, review `improvement_hotspots.json` and bias execution against the top recurring failure modes.",
            "- After each logged issue, this summary and hotspot file are refreshed automatically.",
            "- When a hotspot is fixed, mark it resolved instead of deleting history so future regressions can be identified cleanly.",
        ]
    )
    summary_file.write_text("\n".join(lines_out) + "\n", encoding="utf-8")
