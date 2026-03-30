from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Dict, List

from common import AUDIT_DIR, PhaseStatus, finalize, make_failure_status, read_json, write_text


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build authority graph and sink map.")
    parser.add_argument("--target-dir", required=True)
    return parser.parse_args()


def is_setter_like(function_name: str) -> bool:
    lowered = function_name.lower()
    return (
        lowered.startswith("arm")
        or lowered.startswith("enable")
        or lowered.startswith("disable")
        or lowered.startswith("update")
        or lowered.startswith("configure")
        or lowered.startswith("rotate")
        or lowered.startswith("grant")
        or lowered.startswith("revoke")
        or (lowered.startswith("set") and not lowered.startswith("settle"))
    )


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
        return {"writes": [], "reads": [], "internal_calls": [], "sink_hints": [], "state_keywords": [], "external_calls": []}
    function = functions_by_name.get(function_name)
    if function is None:
        return {"writes": [], "reads": [], "internal_calls": [], "sink_hints": [], "state_keywords": [], "external_calls": []}

    seen = set(seen)
    seen.add(function_name)
    direct_internal_calls = [
        str(item) for item in function.get("internal_calls", [])
        if isinstance(item, str) and item.strip()
    ] if isinstance(function.get("internal_calls"), list) else []

    merged = {
        "writes": merge_lists(function.get("writes")),
        "reads": merge_lists(function.get("state_reads")),
        "internal_calls": merge_lists(direct_internal_calls),
        "sink_hints": merge_lists(function.get("sink_hints")),
        "state_keywords": merge_lists(function.get("state_keywords")),
        "external_calls": merge_lists(function.get("external_calls")),
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
        return {"writes": [], "reads": [], "internal_calls": [], "sink_hints": [], "state_keywords": [], "external_calls": []}
    candidate_contracts = candidate_contracts_for_type(contract_name, contract_metadata)
    if not candidate_contracts:
        return {"writes": [], "reads": [], "internal_calls": [], "sink_hints": [], "state_keywords": [], "external_calls": []}

    seen = set(seen)
    seen.add(key)
    merged = {"writes": [], "reads": [], "internal_calls": [], "sink_hints": [], "state_keywords": [], "external_calls": []}
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
        callee_effects = {"writes": [], "reads": [], "internal_calls": [], "sink_hints": [], "state_keywords": [], "external_calls": []}
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
    artifacts = {"authority_graph": str(AUDIT_DIR / "authority_graph.json")}

    if not target_dir.exists() or not target_dir.is_dir():
        return finalize(
            make_failure_status("authority_graph", errors=[f"Target directory does not exist: {target_dir}"], artifacts=artifacts)
        )

    semantic_index = read_json(AUDIT_DIR / "semantic_index.json")
    files = semantic_index.get("files") if isinstance(semantic_index, dict) else None
    if not isinstance(files, list):
        return finalize(
            make_failure_status("authority_graph", errors=["semantic_index.json is missing or invalid."], artifacts=artifacts)
        )
    contract_metadata = build_contract_metadata(semantic_index.get("contracts"))
    roles: List[str] = []
    edges: List[Dict[str, object]] = []
    sinks: List[Dict[str, object]] = []
    setters: List[Dict[str, object]] = []
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

    for file_entry in files:
        if not isinstance(file_entry, dict):
            continue
        rel = str(file_entry.get("path", ""))
        functions_by_name = {
            str(function.get("name", "")): function
            for function in file_entry.get("functions", [])
            if isinstance(function, dict) and str(function.get("name", "")).strip()
        }
        roles.extend(file_entry.get("role_constants", []) if isinstance(file_entry.get("role_constants"), list) else [])
        for function in file_entry.get("functions", []):
            if not isinstance(function, dict):
                continue
            fn = str(function.get("name", ""))
            visibility = str(function.get("visibility", "internal"))
            owner_contract = str(function.get("contract", "")).strip()
            modifiers = function.get("modifiers") if isinstance(function.get("modifiers"), list) else []
            modifier_guards = [
                str(modifier).strip()
                for modifier in modifiers
                if str(modifier).strip().startswith("only")
            ]
            guards = merge_lists(function.get("auth_guards"), modifier_guards)
            require_guards = function.get("require_guards") if isinstance(function.get("require_guards"), list) else []
            effects = (
                resolve_contract_effects(functions_by_contract, resolved_functions_by_contract, contract_metadata, owner_contract, fn)
                if owner_contract
                else resolve_function_effects(functions_by_name, fn)
            )
            writes = effects.get("writes", [])
            reads = effects.get("reads", [])
            internal_calls = effects.get("internal_calls", [])
            sink_hints = effects.get("sink_hints", [])
            state_keywords = effects.get("state_keywords", []) if isinstance(effects.get("state_keywords"), list) else []
            external_calls = effects.get("external_calls", [])
            direct_writes = function.get("writes") if isinstance(function.get("writes"), list) else []
            direct_external_calls = function.get("external_calls") if isinstance(function.get("external_calls"), list) else []
            direct_sink_hints = function.get("sink_hints") if isinstance(function.get("sink_hints"), list) else []
            setter_like = is_setter_like(fn)
            for guard in guards:
                edges.append({"path": rel, "guard": guard, "function": fn, "kind": "direct_guard"})
            for guard in require_guards:
                edges.append({"path": rel, "guard": guard, "function": fn, "kind": "require_guard"})
            if visibility in {"external", "public"} and direct_sink_hints and direct_writes + direct_external_calls and (not setter_like or direct_external_calls):
                sinks.append(
                    {
                        "path": rel,
                        "contract": owner_contract,
                        "function": fn,
                        "guards": guards,
                        "require_guards": require_guards,
                        "sink_hints": sink_hints,
                        "state_keywords": state_keywords,
                        "writes": writes,
                        "reads": reads,
                        "internal_calls": internal_calls,
                        "external_calls": external_calls,
                        "direct_writes": direct_writes,
                        "direct_external_calls": direct_external_calls,
                        "line_start": function.get("line_start"),
                        "line_end": function.get("line_end"),
                    }
                )
            if visibility in {"external", "public"} and setter_like:
                setters.append(
                    {
                        "path": rel,
                        "contract": owner_contract,
                        "function": fn,
                        "guards": guards,
                        "require_guards": require_guards,
                        "writes": writes,
                        "reads": reads,
                        "internal_calls": internal_calls,
                        "line_start": function.get("line_start"),
                        "line_end": function.get("line_end"),
                    }
                )

    payload = {"roles": sorted(set(roles)), "edges": edges, "sinks": sinks, "setters": setters}

    # Item 11 fallback: when no edges were extracted, pull authority info from semantic_index
    # FunctionEntry.auth_guards and FunctionEntry.sink_hints as a last resort
    if not edges and isinstance(files, list):
        for file_entry in files:
            if not isinstance(file_entry, dict):
                continue
            rel = str(file_entry.get("path", ""))
            for function in file_entry.get("functions", []):
                if not isinstance(function, dict):
                    continue
                fn = str(function.get("name", "")).strip()
                owner_contract = str(function.get("contract", "")).strip()
                if not fn or not owner_contract:
                    continue
                fn_auth_guards = function.get("auth_guards")
                if isinstance(fn_auth_guards, list):
                    for guard in fn_auth_guards:
                        guard_text = str(guard).strip()
                        if guard_text:
                            edges.append({
                                "path": rel, "guard": guard_text,
                                "function": fn, "kind": "semantic_fallback",
                            })
                fn_sink_hints = function.get("sink_hints")
                if isinstance(fn_sink_hints, list) and fn_sink_hints:
                    visibility = str(function.get("visibility", "internal"))
                    if visibility in {"external", "public"}:
                        sinks.append({
                            "path": rel,
                            "contract": owner_contract,
                            "function": fn,
                            "guards": list(fn_auth_guards) if isinstance(fn_auth_guards, list) else [],
                            "require_guards": [],
                            "sink_hints": fn_sink_hints,
                            "state_keywords": [],
                            "writes": function.get("writes", []) if isinstance(function.get("writes"), list) else [],
                            "reads": [],
                            "internal_calls": [],
                            "external_calls": [],
                            "direct_writes": [],
                            "direct_external_calls": [],
                            "line_start": function.get("line_start"),
                            "line_end": function.get("line_end"),
                        })
        payload = {"roles": sorted(set(roles)), "edges": edges, "sinks": sinks, "setters": setters}

    write_text(Path(artifacts["authority_graph"]), json.dumps(payload, indent=2, sort_keys=True) + "\n")
    status = PhaseStatus(
        phase="authority_graph",
        ok=True,
        mode="full",
        artifacts=artifacts,
        warnings=[] if (edges or sinks or setters) else ["No authority edges, setters, or sinks were extracted for this target."],
        errors=[],
        details={"target_dir": str(target_dir), "role_count": len(payload["roles"]), "sink_count": len(sinks), "setter_count": len(setters)},
    )
    return finalize(status)


if __name__ == "__main__":
    raise SystemExit(main())
