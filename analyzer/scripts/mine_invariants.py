from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

from common import AUDIT_DIR, PhaseStatus, finalize, make_failure_status, read_json, write_text


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Mine invariant candidates from semantic artifacts.")
    parser.add_argument("--target-dir", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    artifacts = {"invariant_candidates": str(AUDIT_DIR / "invariant_candidates.json")}
    action_catalog = read_json(AUDIT_DIR / "action_catalog.json")
    authority_graph = read_json(AUDIT_DIR / "authority_graph.json")
    dependency_graph = read_json(AUDIT_DIR / "dependency_graph.json")

    actions = action_catalog.get("actions") if isinstance(action_catalog, dict) else None
    sinks = authority_graph.get("sinks") if isinstance(authority_graph, dict) else None
    setters = authority_graph.get("setters") if isinstance(authority_graph, dict) else None
    dependencies = dependency_graph.get("dependencies") if isinstance(dependency_graph, dict) else None
    if not isinstance(actions, list):
        return finalize(make_failure_status("invariant_candidates", errors=["action_catalog.json is missing or invalid."], artifacts=artifacts))

    invariants: List[Dict[str, object]] = []
    for action in actions:
        if not isinstance(action, dict):
            continue
        fn = str(action.get("function", ""))
        path = str(action.get("path", ""))
        if any(keyword in fn.lower() for keyword in ("settle", "close", "recover")):
            invariants.append({"path": path, "function": fn, "invariant": "Recovery and settlement paths should remain reachable after failure states."})
        if any(keyword in fn.lower() for keyword in ("set", "grant", "revoke", "rotate")):
            invariants.append({"path": path, "function": fn, "invariant": "Authority changes should not leave stale privilege or unreachable safe rotation."})
        if "price" in fn.lower() or "oracle" in fn.lower():
            invariants.append({"path": path, "function": fn, "invariant": "Price-dependent actions should fail closed on stale or inconsistent valuation."})
        if action.get("trust_boundary") and action.get("writes"):
            invariants.append({"path": path, "function": fn, "invariant": "State-changing flows should remain safe when external control is yielded."})

    if isinstance(dependencies, list):
        for dep in dependencies:
            if isinstance(dep, dict) and dep.get("criticality") == "recovery_critical":
                invariants.append({"path": dep.get("path", ""), "function": "not_determined", "invariant": "Recovery-critical dependencies should have a fallback or rotation path."})
    if isinstance(sinks, list):
        for sink in sinks:
            if isinstance(sink, dict) and not sink.get("guards"):
                invariants.append({"path": sink.get("path", ""), "function": sink.get("function", ""), "invariant": "Sensitive sinks should have an explicit authority boundary."})
    if isinstance(setters, list):
        for setter in setters:
            if isinstance(setter, dict) and setter.get("writes") and not setter.get("guards"):
                invariants.append({"path": setter.get("path", ""), "function": setter.get("function", ""), "invariant": "Security-relevant setters should be guarded and rotatable."})

    write_text(Path(artifacts["invariant_candidates"]), json.dumps({"invariants": invariants}, indent=2, sort_keys=True) + "\n")
    status = PhaseStatus(
        phase="invariant_candidates",
        ok=bool(invariants),
        mode="full",
        artifacts=artifacts,
        warnings=[],
        errors=[],
        details={"target_dir": args.target_dir, "invariant_count": len(invariants)},
    )
    return finalize(status)


if __name__ == "__main__":
    raise SystemExit(main())
