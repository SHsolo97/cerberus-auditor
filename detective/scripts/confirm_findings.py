from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from common import AUDIT_DIR, PhaseStatus, finalize, make_failure_status, read_json, write_text


# ── Guard helpers ─────────────────────────────────────────────────────────────

def guard_set(entry: Dict[str, object]) -> set[str]:
    guards = []
    for field in ("guards", "require_guards", "auth_guards"):
        value = entry.get(field)
        if isinstance(value, list):
            guards.extend(str(item) for item in value if str(item).strip())
    return set(guards)


# ── Scope and inheritance helpers ────────────────────────────────────────────

def _load_scope_filter() -> Optional[Set[str]]:
    """Load in-scope file set from contest_context.json."""
    contest = read_json(AUDIT_DIR / "contest_context.json")
    scope_files = contest.get("scope_files") if isinstance(contest, dict) else None
    if not isinstance(scope_files, list) or not scope_files:
        return None
    normalized: Set[str] = set()
    for raw in scope_files:
        if isinstance(raw, str) and raw.strip().endswith(".sol"):
            normalized.add(raw.strip().lstrip("./"))
    return normalized or None


def _build_semantic_metadata() -> Dict[str, Any]:
    """
    Build lookup tables from semantic_index / ast_semantic_index.
    Prefers AST-backed data when available.
    """
    meta: Dict[str, Any] = {
        "interfaces": frozenset(),
        "parent_contracts": frozenset(),
        "contract_to_file": {},
        "contract_inherits": {},
        "contract_kind": {},
        "file_contracts": {},
    }

    for index_name in ("ast_semantic_index", "semantic_index"):
        idx_path = AUDIT_DIR / f"{index_name}.json"
        if not idx_path.exists():
            continue
        data = read_json(idx_path)
        if not isinstance(data, dict):
            continue

        contracts = data.get("contracts", [])
        if not isinstance(contracts, list):
            contracts = []
        files = data.get("files", [])
        if not isinstance(files, list):
            files = []

        # Collect file -> contract names
        file_contracts: Dict[str, List[str]] = {}
        for fentry in files:
            if not isinstance(fentry, dict):
                continue
            fpath = str(fentry.get("path", ""))
            fcontracts = fentry.get("contracts", [])
            if not isinstance(fcontracts, list):
                fcontracts = []
            for c in fcontracts:
                if not isinstance(c, dict):
                    continue
                cname = str(c.get("name", "")).strip()
                if not cname:
                    continue
                kind = str(c.get("kind", "contract")).lower()
                inherits = c.get("inherits")
                if not isinstance(inherits, list):
                    inherits = []
                inherits = [str(i).strip() for i in inherits if str(i).strip()]
                meta["contract_kind"][cname] = kind
                meta["contract_inherits"][cname] = inherits
                meta["contract_to_file"][cname] = fpath
                file_contracts.setdefault(fpath, []).append(cname)

        meta["file_contracts"] = file_contracts
        meta["interfaces"] = frozenset(
            n for n, k in meta["contract_kind"].items() if k == "interface"
        )
        meta["parent_contracts"] = frozenset(
            p
            for parents in meta["contract_inherits"].values()
            for p in parents
        )

        if meta["contract_to_file"]:
            break

    return meta


def _scope_status(
    target_contract: str,
    scope_filter: Optional[Set[str]],
    meta: Dict[str, Any],
) -> str:
    """Returns 'in_scope' | 'out_of_scope' | 'unknown'."""
    if scope_filter is None:
        return "unknown"

    cfile = meta.get("contract_to_file", {}).get(target_contract, "")
    if cfile and (cfile in scope_filter or f"./{cfile}" in scope_filter):
        return "in_scope"

    # Check parent contracts
    inherits = meta.get("contract_inherits", {}).get(target_contract, [])
    for parent in inherits:
        pfile = meta.get("contract_to_file", {}).get(parent, "")
        if pfile and (pfile in scope_filter or f"./{pfile}" in scope_filter):
            return "in_scope"

    return "out_of_scope"


def _parent_guard_status(
    target_functions: List[str],
    target_contract: str,
    meta: Dict[str, Any],
    authority_sinks: List[Dict[str, object]],
) -> Optional[str]:
    """
    Detect parent-guard shadow: sink is in a child contract but the parent
    already guards the same-named function.  Returns a rejection reason
    string if shadow is detected, else None.
    """
    inherits = list(meta.get("contract_inherits", {}).get(target_contract, []))
    if not inherits:
        return None

    for parent in inherits:
        for sink_entry in authority_sinks:
            if not isinstance(sink_entry, dict):
                continue
            sink_fn = str(sink_entry.get("function", ""))
            sink_c = str(sink_entry.get("contract", ""))
            if sink_fn in target_functions and sink_c == parent and guard_set(sink_entry):
                return (
                    f"Function '{sink_fn}' is guarded in parent contract '{parent}'; "
                    f"child '{target_contract}' inherits the guard."
                )
    return None


# ── Confidence boost ─────────────────────────────────────────────────────────

def _confidence_boost(
    status: str,
    scope_st: str,
    parent_guard: Optional[str],
    rejection_reason: Optional[str],
) -> float:
    """Adjust base confidence based on rejection / reinforcement signals."""
    if rejection_reason or status == "rejected":
        return 0.0  # explicit — don't boost
    boost = 0.0
    if scope_st == "out_of_scope":
        boost -= 0.15
    if parent_guard:
        boost -= 0.15
    return max(-0.3, min(0.3, boost))


# ── Argument parsing ─────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Confirm or reject structured finding candidates.",
    )
    parser.add_argument("--target-dir", required=True)
    return parser.parse_args()


# ── Confirmation logic ────────────────────────────────────────────────────────

def _confirm_authority_drift(
    evidence_list: List[Dict[str, object]],
    sinks: List[Dict[str, object]],
    target_list: List[str],
    parent_guard_reason: Optional[str],
) -> tuple[str, str, Optional[str], List[str]]:
    """
    Returns (status, guard_analysis, rejection_reason, disqualifiers).
    """
    guard_analysis = "Needs repo-specific follow-up."
    disqualifiers: List[str] = []
    rejection_reason: Optional[str] = None
    status = "weak_signal"

    # Rejection: parent guard shadow
    if parent_guard_reason:
        rejection_reason = parent_guard_reason
        return "rejected", guard_analysis, rejection_reason, disqualifiers

    paired_evidence = next(
        (
            item for item in evidence_list
            if isinstance(item, dict)
            and isinstance(item.get("setter"), dict)
            and isinstance(item.get("sink"), dict)
        ),
        None,
    )
    matched_sink = next(
        (s for s in sinks
         if isinstance(s, dict) and str(s.get("function", "")) in target_list),
        None,
    )

    if paired_evidence is not None:
        setter_info = paired_evidence.get("setter", {})
        sink_info = paired_evidence.get("sink", {})
        setter_guards = guard_set(setter_info)
        sink_guards = guard_set(sink_info)
        shared_writes = paired_evidence.get("shared_writes", [])

        if setter_guards == sink_guards and setter_guards:
            rejection_reason = (
                f"Setter and sink share the same guard surface "
                f"({', '.join(sorted(setter_guards))}); "
                "authority cannot drift between them."
            )
            status = "rejected"
        elif setter_guards != sink_guards and shared_writes:
            status = "source_confirmed"
            guard_analysis = (
                "Confirmed setter and sink use different guard surfaces "
                "while touching shared state "
                f"({', '.join(str(w) for w in shared_writes[:4])})."
            )
    elif matched_sink is not None and not matched_sink.get("guards"):
        status = "source_confirmed"
        line_start = matched_sink.get("line_start")
        guard_analysis = (
            "Confirmed target sink has no explicit guard in structured "
            "authority extraction."
            + (f" Sink starts near line {line_start}." if line_start else "")
        )

    return status, guard_analysis, rejection_reason, disqualifiers


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    args = parse_args()
    artifacts = {"finding_confirmations": str(AUDIT_DIR / "finding_confirmations.json")}

    finding_candidates = read_json(AUDIT_DIR / "finding_candidates.json")
    authority_graph = read_json(AUDIT_DIR / "authority_graph.json")
    action_catalog = read_json(AUDIT_DIR / "action_catalog.json")
    findings = finding_candidates.get("findings") if isinstance(finding_candidates, dict) else None

    if not isinstance(findings, list):
        return finalize(make_failure_status(
            "finding_confirmation",
            errors=["finding_candidates.json is missing or invalid."],
            artifacts=artifacts,
        ))

    sinks = authority_graph.get("sinks") if isinstance(authority_graph, dict) else []
    setters = authority_graph.get("setters") if isinstance(authority_graph, dict) else []
    actions = action_catalog.get("actions") if isinstance(action_catalog, dict) else []

    scope_filter = _load_scope_filter()
    meta = _build_semantic_metadata()

    confirmed: List[Dict[str, object]] = []
    for finding in findings:
        if not isinstance(finding, dict):
            continue

        target_functions = finding.get("target_functions")
        evidence = finding.get("evidence")
        target_list = target_functions if isinstance(target_functions, list) else []
        evidence_list = evidence if isinstance(evidence, list) else []
        family = str(finding.get("family", ""))
        target_contract = str(finding.get("target_contract", "")).strip()
        base_confidence = float(finding.get("confidence_score", 0.5))
        base_disqualifiers = list(finding.get("blocking_unknowns", []))

        guard_analysis = "Needs repo-specific follow-up."
        disqualifiers: List[str] = list(base_disqualifiers)
        rejection_reason: Optional[str] = None
        status = "weak_signal"
        scope_status_val = "unknown"

        # ── Universal: dead code (interface-only sink) ────────────────────────
        if target_contract:
            target_kind = meta.get("contract_kind", {}).get(target_contract, "contract")
            if target_kind == "interface":
                rejection_reason = (
                    "Sink function is declared in an interface; no implementation body."
                )
                status = "rejected"

        # ── Universal: scope disqualification ────────────────────────────────
        if status != "rejected":
            scope_status_val = _scope_status(target_contract, scope_filter, meta)
            if scope_status_val == "out_of_scope":
                disqualifiers = [
                    "Target is outside contest scope."
                ] + disqualifiers

        # ── Universal: parent guard shadow ────────────────────────────────
        parent_guard_reason = _parent_guard_status(
            target_list, target_contract, meta, sinks,
        )

        # ── Family-specific confirmation ────────────────────────────────
        if family == "authority_drift" and status != "rejected":
            status, guard_analysis, rejection_reason, disqualifiers = (
                _confirm_authority_drift(
                    evidence_list, sinks, target_list, parent_guard_reason,
                )
            )
            # Setter-path disqualifier
            if status != "rejected" and isinstance(setters, list):
                setter_hit = next(
                    (
                        s for s in setters
                        if isinstance(s, dict)
                        and str(s.get("function", "")) in target_list
                    ),
                    None,
                )
                if setter_hit is not None and setter_hit.get("guards"):
                    disqualifiers = list(disqualifiers) + [
                        "Setter path is guarded; confirm whether mismatch still creates risk."
                    ]
        elif family == "callback_state_drift":
            matched_action = next(
                (
                    a for a in actions
                    if isinstance(a, dict) and str(a.get("function", "")) in target_list
                ),
                None,
            )
            if (
                matched_action is not None
                and matched_action.get("trust_boundary")
                and matched_action.get("writes")
            ):
                status = "source_confirmed"
                writes = ", ".join(str(w) for w in matched_action.get("writes", [])[:4])
                guard_analysis = (
                    "Confirmed external control is yielded in a state-mutating action"
                    + (f" touching {writes}." if writes else ".")
                )
        elif family == "broken_recovery":
            matched_action = next(
                (
                    a for a in actions
                    if isinstance(a, dict) and str(a.get("function", "")) in target_list
                ),
                None,
            )
            if matched_action is not None and any(
                kw in matched_action.get("state_keywords", [])
                for kw in ("recover", "settle", "close")
            ):
                status = "source_confirmed"
                reads = matched_action.get("state_reads", [])
                guard_analysis = (
                    "Confirmed recovery-style action exists."
                    + (
                        f" Reads state {', '.join(str(r) for r in reads[:4])}."
                        if reads else ""
                    )
                )
        elif family == "dependency_recovery_lockup":
            status = "weak_signal" if not target_list else "source_confirmed"
            guard_analysis = "Dependency is recovery-critical per structured dependency analysis."
        elif family == "settlement_dependency_drift":
            status = "weak_signal" if not target_list else "source_confirmed"
            guard_analysis = "Dependency is settlement-critical per structured dependency analysis."
        elif family == "implementation_rebinding":
            paired_evidence = next(
                (
                    item for item in evidence_list
                    if isinstance(item, dict)
                    and (
                        isinstance(item.get("setter"), dict)
                        or (
                            isinstance(item.get("setters"), list)
                            and any(isinstance(s, dict) for s in item.get("setters", []))
                        )
                    )
                    and isinstance(item.get("sink"), dict)
                ),
                None,
            )
            if paired_evidence is not None:
                setters_seq = (
                    [s for s in paired_evidence.get("setters", []) if isinstance(s, dict)]
                    if isinstance(paired_evidence.get("setters"), list) else []
                )
                setter_info = setters_seq[0] if setters_seq else paired_evidence.get("setter", {})
                sink_info = paired_evidence.get("sink", {})
                slot_name = str(paired_evidence.get("slot", "")).strip()
                slot_type = str(paired_evidence.get("slot_type", "")).strip()
                bound_types = [
                    str(bt).strip()
                    for bt in paired_evidence.get("bound_types", [])
                    if str(bt).strip()
                ] if isinstance(paired_evidence.get("bound_types"), list) else []

                if slot_name and target_list:
                    status = "source_confirmed"
                    sink_fn = str(sink_info.get("function", "")) or (
                        target_list[-1] if target_list else "not_determined"
                    )
                    setter_fns = [
                        str(s.get("function", "")).strip()
                        for s in setters_seq
                        if str(s.get("function", "")).strip()
                    ] or [str(setter_info.get("function", "setter")).strip() or "setter"]
                    guard_analysis = (
                        f"Confirmed {' -> '.join(setter_fns)} can rebind contract slot "
                        f"{slot_name}" + (f" ({slot_type})" if slot_type else "")
                        + f" that feeds {sink_fn}."
                        + (
                            f" Candidate implementations: {', '.join(bound_types[:4])}."
                            if bound_types else ""
                        )
                    )
                    disqualifiers = list(disqualifiers) + [
                        "Confirm rebound implementation is reachable in production wiring.",
                    ]
        elif target_list and evidence_list:
            status = "source_confirmed"
            guard_analysis = "Structural confirmation succeeded."

        # ── Confidence adjustment ─────────────────────────────────────────
        boost = _confidence_boost(
            status, scope_status_val, parent_guard_reason, rejection_reason,
        )
        final_confidence = round(max(0.0, min(1.0, base_confidence + boost)), 2)

        # ── Final disqualifier: parent guard shadow ────────────────────────
        if parent_guard_reason and "parent guard" not in " ".join(disqualifiers).lower():
            disqualifiers = list(disqualifiers) + [
                f"Parent contract guards the sink: {parent_guard_reason}"
            ]

        # ── Build confirmation entry ──────────────────────────────────────
        target_action = next(
            (
                a for a in actions
                if isinstance(a, dict)
                and str(a.get("function", "")) == (target_list[0] if target_list else None)
            ),
            None,
        )
        line_ref = (
            f":{target_action.get('line_start')}"
            if isinstance(target_action, dict) and target_action.get("line_start")
            else ""
        )

        confirmed.append({
            "candidate_id": str(finding.get("id", "")),
            "title": str(finding.get("title", "")),
            "status": status,
            "rejection_reason": rejection_reason,
            "scope_status": scope_status_val,
            "confidence_score": final_confidence,
            "confidence_boost": boost,
            "source_paths": [str(finding.get("target_contract", "")) + line_ref],
            "sink_function": (
                target_list[-1]
                if family == "implementation_rebinding" and target_list
                else (target_list[0] if target_list else "not_determined")
            ),
            "guard_analysis": guard_analysis,
            "state_argument": str(finding.get("violated_invariant", "")),
            "disqualifiers": disqualifiers,
        })

    write_text(
        Path(artifacts["finding_confirmations"]),
        json.dumps({"findings": confirmed}, indent=2, sort_keys=True) + "\n",
    )
    no_candidates_info = (
        "No structured finding candidates required confirmation for this target."
        if not confirmed
        else ""
    )
    status_obj = PhaseStatus(
        phase="finding_confirmation",
        ok=True,
        mode="full",
        artifacts=artifacts,
        warnings=[],
        errors=[],
        details={
            "target_dir": args.target_dir,
            "confirmed_count": len(confirmed),
            "rejected_count": sum(1 for c in confirmed if c.get("status") == "rejected"),
            "no_confirmation_needed": no_candidates_info,
        },
    )
    return finalize(status_obj)


if __name__ == "__main__":
    raise SystemExit(main())
