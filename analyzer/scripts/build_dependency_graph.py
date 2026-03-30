from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List

from common import AUDIT_DIR, PhaseStatus, discover_solidity_files, finalize, make_failure_status, read_json, write_text


DEPENDENCY_PATTERNS = {
    "oracle": re.compile(r"oracle|latestRoundData|latestAnswer|priceFeed|chainlink", re.IGNORECASE),
    "registry": re.compile(r"registry", re.IGNORECASE),
    "bridge": re.compile(r"bridge|messenger", re.IGNORECASE),
    "proxy": re.compile(r"proxy|implementation|upgradeTo", re.IGNORECASE),
    "callback": re.compile(r"hook|callback|onERC|receive\(", re.IGNORECASE),
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build dependency graph for external trust boundaries.")
    parser.add_argument("--target-dir", required=True)
    return parser.parse_args()


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def criticality(dep_type: str) -> str:
    if dep_type in {"oracle", "bridge"}:
        return "settlement_critical"
    if dep_type in {"registry", "proxy"}:
        return "recovery_critical"
    if dep_type == "callback":
        return "gating"
    return "informational"


def build_contract_index(semantic_index: object) -> tuple[Dict[str, str], Dict[str, List[str]]]:
    contracts = semantic_index.get("contracts") if isinstance(semantic_index, dict) else None
    contract_to_path: Dict[str, str] = {}
    inherits_by_contract: Dict[str, List[str]] = {}
    if not isinstance(contracts, list):
        return contract_to_path, inherits_by_contract
    for contract in contracts:
        if not isinstance(contract, dict):
            continue
        name = str(contract.get("name", "")).strip()
        path = str(contract.get("path", "")).strip()
        if not name:
            continue
        if path:
            contract_to_path[name] = path
        inherits_by_contract[name] = [
            str(item).strip()
            for item in contract.get("inherits", [])
            if str(item).strip()
        ] if isinstance(contract.get("inherits"), list) else []
    return contract_to_path, inherits_by_contract


def main() -> int:
    args = parse_args()
    target_dir = Path(args.target_dir).resolve()
    artifacts = {"dependency_graph": str(AUDIT_DIR / "dependency_graph.json")}

    if not target_dir.exists() or not target_dir.is_dir():
        return finalize(
            make_failure_status("dependency_graph", errors=[f"Target directory does not exist: {target_dir}"], artifacts=artifacts)
        )

    files = discover_solidity_files(target_dir)
    dependencies: List[Dict[str, object]] = []
    semantic_index = read_json(AUDIT_DIR / "semantic_index.json")
    contract_to_path, inherits_by_contract = build_contract_index(semantic_index)
    for path in files:
        text = read_text(path)
        rel = path.relative_to(target_dir.parent).as_posix()
        for dep_type, pattern in DEPENDENCY_PATTERNS.items():
            hits = len(pattern.findall(text))
            if hits:
                dependencies.append({"path": rel, "type": dep_type, "hits": hits, "criticality": criticality(dep_type)})

    path_dependencies: Dict[str, Dict[str, Dict[str, object]]] = {}
    for dependency in dependencies:
        dep_path = str(dependency.get("path", "")).strip()
        dep_type = str(dependency.get("type", "")).strip()
        if not dep_path or not dep_type:
            continue
        path_dependencies.setdefault(dep_path, {})[dep_type] = dependency

    propagated: List[Dict[str, object]] = []
    for contract_name, parents in inherits_by_contract.items():
        child_path = contract_to_path.get(contract_name)
        if not child_path:
            continue
        for parent in parents:
            parent_path = contract_to_path.get(parent)
            if not parent_path:
                continue
            for dep_type, dependency in path_dependencies.get(parent_path, {}).items():
                if dep_type in path_dependencies.get(child_path, {}):
                    continue
                propagated.append(
                    {
                        "path": child_path,
                        "type": dep_type,
                        "hits": int(dependency.get("hits", 1)),
                        "criticality": str(dependency.get("criticality", criticality(dep_type))),
                        "derived_from": parent_path,
                    }
                )

    dependencies.extend(propagated)

    write_text(Path(artifacts["dependency_graph"]), json.dumps({"dependencies": dependencies}, indent=2, sort_keys=True) + "\n")
    status = PhaseStatus(
        phase="dependency_graph",
        ok=True,
        mode="full",
        artifacts=artifacts,
        warnings=[],
        errors=[],
        details={"target_dir": str(target_dir), "dependency_count": len(dependencies)},
    )
    return finalize(status)


if __name__ == "__main__":
    raise SystemExit(main())
