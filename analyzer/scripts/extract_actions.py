from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List

from common import AUDIT_DIR, PhaseStatus, finalize, make_failure_status, read_json, write_text


READ_HINT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")
VALUE_HINTS = ("transfer", "transferFrom", "safeTransfer", "safeTransferFrom", "mint", "burn", "withdraw", "redeem", "claim", "sweep")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract action catalog and state transitions.")
    parser.add_argument("--target-dir", required=True)
    return parser.parse_args()


def merge_lists(*values: object) -> List[str]:
    merged: List[str] = []
    seen: set[str] = set()
    for value in values:
        if not isinstance(value, list):
            continue
        for item in value:
            text = str(item).strip()
            if text and text not in seen:
                seen.add(text)
                merged.append(text)
    return merged


def build_contract_metadata(contracts: object) -> Dict[str, Dict[str, object]]:
    metadata: Dict[str, Dict[str, object]] = {}
    if not isinstance(contracts, list):
        return metadata
    for contract in contracts:
        if not isinstance(contract, dict):
            continue
        name = str(contract.get("name", "")).strip()
        if not name:
            continue
        inherits = [
            str(item).strip()
            for item in contract.get("inherits", [])
            if str(item).strip()
        ] if isinstance(contract.get("inherits"), list) else []
        metadata[name] = {
            "kind": str(contract.get("kind", "")),
            "inherits": inherits,
        }
    return metadata


def build_resolved_function_map(
    contract_name: str,
    functions_by_contract: Dict[str, Dict[str, Dict[str, object]]],
    contract_metadata: Dict[str, Dict[str, object]],
    seen: set[str] | None = None,
) -> Dict[str, Dict[str, object]]:
    if seen is None:
        seen = set()
    if contract_name in seen:
        return {}
    seen = set(seen)
    seen.add(contract_name)
    merged: Dict[str, Dict[str, object]] = {}
    metadata = contract_metadata.get(contract_name, {})
    for parent in metadata.get("inherits", []):
        for function_name, function in build_resolved_function_map(parent, functions_by_contract, contract_metadata, seen).items():
            merged.setdefault(function_name, function)
    for function_name, function in functions_by_contract.get(contract_name, {}).items():
        merged[function_name] = function
    return merged


def candidate_contracts_for_type(contract_type: str, contract_metadata: Dict[str, Dict[str, object]], preferred_types: List[str] | None = None) -> List[str]:
    if preferred_types:
        preferred = [item for item in preferred_types if item in contract_metadata]
        if preferred:
            return preferred
    direct = [contract_type] if contract_type in contract_metadata else []
    implementers = [
        name
        for name, metadata in contract_metadata.items()
        if contract_type in metadata.get("inherits", [])
    ]
    return direct + [name for name in implementers if name not in direct]


def resolve_function_effects(functions_by_name: Dict[str, Dict[str, object]], function_name: str, seen: set[str] | None = None) -> Dict[str, List[str]]:
    if seen is None:
        seen = set()
    if function_name in seen:
        return {
            "writes": [],
            "state_reads": [],
            "external_calls": [],
            "internal_calls": [],
            "sink_hints": [],
            "state_keywords": [],
        }
    function = functions_by_name.get(function_name)
    if function is None:
        return {
            "writes": [],
            "state_reads": [],
            "external_calls": [],
            "internal_calls": [],
            "sink_hints": [],
            "state_keywords": [],
        }

    seen = set(seen)
    seen.add(function_name)
    direct_internal_calls = [
        str(item) for item in function.get("internal_calls", [])
        if isinstance(item, str) and item.strip()
    ] if isinstance(function.get("internal_calls"), list) else []

    merged = {
        "writes": merge_lists(function.get("writes")),
        "state_reads": merge_lists(function.get("state_reads")),
        "external_calls": merge_lists(function.get("external_calls")),
        "internal_calls": merge_lists(direct_internal_calls),
        "sink_hints": merge_lists(function.get("sink_hints")),
        "state_keywords": merge_lists(function.get("state_keywords")),
    }
    for callee_name in direct_internal_calls:
        callee_effects = resolve_function_effects(functions_by_name, callee_name, seen)
        for key in merged:
            merged[key] = merge_lists(merged[key], callee_effects.get(key))
    return merged


def resolve_contract_effects(
    functions_by_contract: Dict[str, Dict[str, Dict[str, object]]],
    resolved_functions_by_contract: Dict[str, Dict[str, Dict[str, object]]],
    contract_metadata: Dict[str, Dict[str, object]],
    contract_name: str,
    function_name: str,
    seen: set[tuple[str, str]] | None = None,
) -> Dict[str, List[str]]:
    if seen is None:
        seen = set()
    key = (contract_name, function_name)
    if key in seen:
        return {
            "writes": [],
            "state_reads": [],
            "external_calls": [],
            "internal_calls": [],
            "sink_hints": [],
            "state_keywords": [],
        }
    candidate_contracts = candidate_contracts_for_type(contract_name, contract_metadata)
    if not candidate_contracts:
        return {
            "writes": [],
            "state_reads": [],
            "external_calls": [],
            "internal_calls": [],
            "sink_hints": [],
            "state_keywords": [],
        }

    seen = set(seen)
    seen.add(key)
    merged = {
        "writes": [],
        "state_reads": [],
        "external_calls": [],
        "internal_calls": [],
        "sink_hints": [],
        "state_keywords": [],
    }
    function = None
    for candidate_contract in candidate_contracts:
        functions_by_name = resolved_functions_by_contract.get(candidate_contract, {})
        if function_name not in functions_by_name:
            continue
        candidate_effects = resolve_function_effects(functions_by_name, function_name)
        for effect_key in merged:
            merged[effect_key] = merge_lists(merged.get(effect_key), candidate_effects.get(effect_key))
        if function is None:
            function = functions_by_name.get(function_name)
    member_calls = function.get("member_calls", []) if isinstance(function, dict) and isinstance(function.get("member_calls"), list) else []
    for member_call in member_calls:
        if not isinstance(member_call, dict):
            continue
        receiver_type = str(member_call.get("receiver_type", "")).strip()
        called_function = str(member_call.get("function", "")).strip()
        preferred_types = [
            str(item).strip()
            for item in member_call.get("bound_types", [])
            if str(item).strip()
        ] if isinstance(member_call.get("bound_types"), list) else []
        if not receiver_type or not called_function or receiver_type == contract_name:
            continue
        candidate_targets = candidate_contracts_for_type(receiver_type, contract_metadata, preferred_types)
        callee_effects = {
            "writes": [],
            "state_reads": [],
            "external_calls": [],
            "internal_calls": [],
            "sink_hints": [],
            "state_keywords": [],
        }
        for candidate_target in candidate_targets:
            target_effects = resolve_contract_effects(
                functions_by_contract,
                resolved_functions_by_contract,
                contract_metadata,
                candidate_target,
                called_function,
                seen,
            )
            for effect_key in callee_effects:
                callee_effects[effect_key] = merge_lists(callee_effects.get(effect_key), target_effects.get(effect_key))
        for effect_key in merged:
            merged[effect_key] = merge_lists(merged.get(effect_key), callee_effects.get(effect_key))
    return merged


def main() -> int:
    args = parse_args()
    target_dir = Path(args.target_dir).resolve()
    artifacts = {
        "action_catalog": str(AUDIT_DIR / "action_catalog.json"),
        "state_transition_map": str(AUDIT_DIR / "state_transition_map.json"),
    }

    if not target_dir.exists() or not target_dir.is_dir():
        return finalize(
            make_failure_status("action_catalog", errors=[f"Target directory does not exist: {target_dir}"], artifacts=artifacts)
        )

    semantic_index = read_json(AUDIT_DIR / "semantic_index.json")
    files = semantic_index.get("files") if isinstance(semantic_index, dict) else None
    if not isinstance(files, list):
        return finalize(
            make_failure_status("action_catalog", errors=["semantic_index.json is missing or invalid."], artifacts=artifacts)
        )
    contract_metadata = build_contract_metadata(semantic_index.get("contracts"))
    functions_by_contract: Dict[str, Dict[str, Dict[str, object]]] = {}
    for file_entry in files:
        if not isinstance(file_entry, dict):
            continue
        for function in file_entry.get("functions", []):
            if not isinstance(function, dict):
                continue
            contract_name = str(function.get("contract", "")).strip()
            function_name = str(function.get("name", "")).strip()
            if not contract_name or not function_name:
                continue
            functions_by_contract.setdefault(contract_name, {})[function_name] = function
    resolved_functions_by_contract = {
        contract_name: build_resolved_function_map(contract_name, functions_by_contract, contract_metadata)
        for contract_name in contract_metadata
    }
    actions: List[Dict[str, object]] = []
    transitions: List[Dict[str, object]] = []
    for file_entry in files:
        if not isinstance(file_entry, dict):
            continue
        rel = str(file_entry.get("path", ""))
        functions_by_name = {
            str(function.get("name", "")): function
            for function in file_entry.get("functions", [])
            if isinstance(function, dict) and str(function.get("name", "")).strip()
        }
        state_var_names = {
            str(item.get("name", ""))
            for item in file_entry.get("state_vars", [])
            if isinstance(item, dict) and str(item.get("name", "")).strip()
        }
        for function in file_entry.get("functions", []):
            if not isinstance(function, dict):
                continue
            name = str(function.get("name", ""))
            visibility = str(function.get("visibility", "internal"))
            if visibility not in {"external", "public"}:
                continue
            owner_contract = str(function.get("contract", "")).strip()
            effects = (
                resolve_contract_effects(functions_by_contract, resolved_functions_by_contract, contract_metadata, owner_contract, name)
                if owner_contract
                else resolve_function_effects(functions_by_name, name)
            )
            writes = effects.get("writes", [])
            external_calls = effects.get("external_calls", [])
            internal_calls = effects.get("internal_calls", [])
            sink_hints = effects.get("sink_hints", [])
            state_keywords = effects.get("state_keywords", [])
            auth_guards = function.get("auth_guards") if isinstance(function.get("auth_guards"), list) else []
            require_guards = function.get("require_guards") if isinstance(function.get("require_guards"), list) else []
            modifiers = function.get("modifiers") if isinstance(function.get("modifiers"), list) else []
            params = str(function.get("params", ""))
            param_reads = [token for token in sorted(set(READ_HINT_RE.findall(params))) if token not in {"address", "uint256", "bool", "bytes32"}][:12]
            state_reads = [
                token for token in effects.get("state_reads", [])
                if isinstance(token, str) and token in state_var_names
            ]
            reads = sorted(set(param_reads + state_reads))[:16]
            action = {
                "path": rel,
                "contract": owner_contract,
                "function": name,
                "visibility": visibility,
                "writes": writes,
                "state_reads": state_reads,
                "external_calls": external_calls,
                "internal_calls": internal_calls,
                "reads": reads,
                "auth_guards": auth_guards,
                "require_guards": require_guards,
                "modifiers": modifiers,
                "sink_hints": sink_hints,
                "state_keywords": state_keywords,
                "emits_value": any(token in name.lower() for token in VALUE_HINTS) or any(call in VALUE_HINTS for call in external_calls),
                "trust_boundary": bool(external_calls),
                "line_start": function.get("line_start"),
                "line_end": function.get("line_end"),
            }
            actions.append(action)
            transitions.append(
                {
                    "path": rel,
                    "contract": owner_contract,
                    "function": name,
                    "writes_state": bool(writes),
                    "reads_state": bool(state_reads),
                    "calls_external": bool(external_calls),
                    "calls_internal": bool(internal_calls),
                    "changes_authority": any(token in name.lower() for token in ("grant", "revoke", "rotate", "set", "update")),
                    "touches_sink": bool(sink_hints),
                    "keywords": state_keywords,
                }
            )

    write_text(Path(artifacts["action_catalog"]), json.dumps({"actions": actions}, indent=2, sort_keys=True) + "\n")
    write_text(Path(artifacts["state_transition_map"]), json.dumps({"transitions": transitions}, indent=2, sort_keys=True) + "\n")
    status = PhaseStatus(
        phase="action_catalog",
        ok=bool(actions),
        mode="full",
        artifacts=artifacts,
        warnings=[],
        errors=[],
        details={"target_dir": str(target_dir), "action_count": len(actions)},
    )
    return finalize(status)


if __name__ == "__main__":
    raise SystemExit(main())
