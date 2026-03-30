from __future__ import annotations

import argparse
import json
from pathlib import Path
from itertools import combinations
from typing import Dict, List

from common import AUDIT_DIR, PhaseStatus, finalize, make_failure_status, read_json, write_text

MAX_REBINDING_RELAY_DEPTH = 8


def guard_set(entry: Dict[str, object]) -> set[str]:
    guards = []
    for field in ("guards", "require_guards", "auth_guards", "modifiers"):
        value = entry.get(field)
        if isinstance(value, list):
            guards.extend(str(item) for item in value if str(item).strip())
    return set(guards)


def is_contract_typed(type_name: object) -> bool:
    text = str(type_name or "").strip()
    return bool(text) and text[0].isupper()


def merge_unique(items: List[str]) -> List[str]:
    seen: set[str] = set()
    merged: List[str] = []
    for item in items:
        text = str(item).strip()
        if text and text not in seen:
            seen.add(text)
            merged.append(text)
    return merged


def semantic_writes(function: Dict[str, object]) -> List[str]:
    return [
        str(item).strip()
        for item in function.get("writes", [])
        if str(item).strip()
    ] if isinstance(function.get("writes"), list) else []


# ── Item 12: Contradiction-backed finding candidates ──────────────────────────────────

def _build_contradiction_candidates(
    invariant_entries: List[Dict[str, object]],
    semantic_files: List[Dict[str, object]],
) -> List[Dict[str, object]]:
    """Find contradiction-backed candidates: functions that violate invariants.

    For each invariant, look for functions that read/write the invariant's state
    variables in a way that can violate the invariant. Add as contradiction findings.
    """
    candidates: List[Dict[str, object]] = []
    # Build function index: contract → function → FunctionEntry
    function_index: Dict[tuple[str, str], Dict[str, object]] = {}
    for file_entry in (semantic_files or []):
        if not isinstance(file_entry, dict):
            continue
        for fn in file_entry.get("functions", []):
            if not isinstance(fn, dict):
                continue
            contract = str(fn.get("contract", "")).strip()
            fn_name = str(fn.get("name", "")).strip()
            if contract and fn_name:
                function_index[(contract, fn_name)] = fn

    for invariant in (invariant_entries or []):
        if not isinstance(invariant, dict):
            continue
        inv_id = str(invariant.get("id", "")).strip()
        inv_family = str(invariant.get("family", "")).strip()
        inv_var = str(invariant.get("state_variable", "")).strip()
        inv_desc = str(invariant.get("description", "")).strip()
        inv_assertion = str(invariant.get("assertion", "")).strip()
        if not inv_var or not inv_id:
            continue

        # Find functions that write the invariant's state variable
        violating_functions: List[Dict[str, object]] = []
        for (contract, fn_name), fn_entry in function_index.items():
            writes = semantic_writes(fn_entry)
            reads = [
                str(item).strip()
                for item in fn_entry.get("reads", [])
                if str(item).strip()
            ] if isinstance(fn_entry.get("reads"), list) else []
            # Check if this function writes or reads the invariant's state variable
            var_name = inv_var.split(".")[-1]  # handle "contract.var" → "var"
            if any(var_name in w or w in var_name for w in writes):
                violating_functions.append(fn_entry)
            elif any(var_name in r or r in var_name for r in reads):
                # Read-only functions don't directly violate but can be part of the chain
                pass

        if violating_functions:
            # Pick the first violating function as the candidate anchor
            vf = violating_functions[0]
            vf_name = str(vf.get("name", ""))
            vf_contract = str(vf.get("contract", ""))
            vf_path = str(vf.get("path", ""))
            vf_line = vf.get("line_start")

            candidates.append({
                "id": f"fc-contradiction-{inv_id}",
                "family": inv_family or "generic",
                "violated_invariant": inv_desc,
                "assertion": inv_assertion,
                "target_contract": vf_contract,
                "target_functions": [vf_name],
                "confidence_score": 0.75,
                "evidence": [
                    {
                        "type": "contradiction",
                        "invariant_id": inv_id,
                        "violating_function": vf_name,
                        "state_variable": inv_var,
                        "path": vf_path,
                        "line": vf_line,
                    }
                ],
                "blocking_unknowns": [],
            })

    return candidates


def semantic_true_writes(function: Dict[str, object]) -> List[str]:
    return [
        str(item).strip()
        for item in function.get("true_writes", [])
        if str(item).strip()
    ] if isinstance(function.get("true_writes"), list) else []


def semantic_false_writes(function: Dict[str, object]) -> List[str]:
    return [
        str(item).strip()
        for item in function.get("false_writes", [])
        if str(item).strip()
    ] if isinstance(function.get("false_writes"), list) else []


def parse_param_types(params: object) -> List[str]:
    values: List[str] = []
    for raw_param in str(params or "").split(","):
        raw = raw_param.strip()
        if not raw:
            continue
        tokens = [
            token for token in raw.split()
            if token not in {"memory", "calldata", "storage", "payable"}
        ]
        if len(tokens) < 2:
            continue
        param_type = tokens[-2].strip()
        if param_type:
            values.append(param_type)
    return values


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Generate structured finding candidates from semantic contradictions.")
    parser.add_argument("--target-dir", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    artifacts = {"finding_candidates": str(AUDIT_DIR / "finding_candidates.json")}
    authority_graph = read_json(AUDIT_DIR / "authority_graph.json")
    dependency_graph = read_json(AUDIT_DIR / "dependency_graph.json")
    action_catalog = read_json(AUDIT_DIR / "action_catalog.json")
    invariants = read_json(AUDIT_DIR / "invariant_candidates.json")
    semantic_index = read_json(AUDIT_DIR / "semantic_index.json")

    sinks = authority_graph.get("sinks") if isinstance(authority_graph, dict) else None
    setters = authority_graph.get("setters") if isinstance(authority_graph, dict) else None
    dependencies = dependency_graph.get("dependencies") if isinstance(dependency_graph, dict) else None
    actions = action_catalog.get("actions") if isinstance(action_catalog, dict) else None
    invariant_entries = invariants.get("invariants") if isinstance(invariants, dict) else None
    semantic_files = semantic_index.get("files") if isinstance(semantic_index, dict) else None

    if not isinstance(actions, list):
        return finalize(make_failure_status("finding_candidates", errors=["action_catalog.json is missing or invalid."], artifacts=artifacts))

    findings: List[Dict[str, object]] = []
    seen_ids: set[str] = set()
    function_semantics: Dict[tuple[str, str], Dict[str, object]] = {}
    contract_functions: Dict[str, Dict[str, Dict[str, object]]] = {}
    contract_paths: Dict[str, str] = {}
    state_slots: Dict[str, Dict[str, Dict[str, object]]] = {}
    path_contracts: Dict[str, List[str]] = {}
    contract_kinds: Dict[str, str] = {}
    contract_inherits: Dict[str, List[str]] = {}
    slot_types_by_path: Dict[str, Dict[str, str]] = {}
    concrete_bindings_by_interface: Dict[str, set[str]] = {}
    if isinstance(semantic_files, list):
        for file_entry in semantic_files:
            if not isinstance(file_entry, dict):
                continue
            rel = str(file_entry.get("path", ""))
            contract_names: List[str] = []
            for contract in file_entry.get("contracts", []):
                if not isinstance(contract, dict):
                    continue
                contract_name = str(contract.get("name", "")).strip()
                if not contract_name:
                    continue
                contract_names.append(contract_name)
                contract_kinds[contract_name] = str(contract.get("kind", "")).strip()
                contract_inherits[contract_name] = [
                    str(item).strip()
                    for item in contract.get("inherits", [])
                    if str(item).strip()
                ] if isinstance(contract.get("inherits"), list) else []
                contract_paths[contract_name] = rel
            if contract_names:
                path_contracts[rel] = contract_names
            state_bindings = file_entry.get("state_bindings", {}) if isinstance(file_entry.get("state_bindings"), dict) else {}
            slot_map: Dict[str, Dict[str, object]] = {}
            slot_type_map: Dict[str, str] = {}
            for state_var in file_entry.get("state_vars", []):
                if not isinstance(state_var, dict):
                    continue
                slot_name = str(state_var.get("name", "")).strip()
                if not slot_name:
                    continue
                slot_type = str(state_var.get("type", "")).strip()
                slot_map[slot_name] = {
                    "type": slot_type,
                    "bound_types": [
                        str(item).strip()
                        for item in state_bindings.get(slot_name, [])
                        if str(item).strip()
                    ],
                }
                slot_type_map[slot_name] = slot_type
                concrete_bound_types = {
                    bound_type
                    for bound_type in slot_map[slot_name]["bound_types"]
                    if bound_type and bound_type != slot_type
                }
                if slot_type and concrete_bound_types:
                    concrete_bindings_by_interface.setdefault(slot_type, set()).update(concrete_bound_types)
            state_slots[rel] = slot_map
            slot_types_by_path[rel] = slot_type_map
            for function in file_entry.get("functions", []):
                if not isinstance(function, dict):
                    continue
                function_name = str(function.get("name", "")).strip()
                if function_name:
                    function_semantics[(rel, function_name)] = function
            function_map = {
                str(function.get("name", "")).strip(): function
                for function in file_entry.get("functions", [])
                if isinstance(function, dict) and str(function.get("name", "")).strip()
            }
            for contract_name in contract_names:
                contract_functions[contract_name] = function_map

    interface_names = {
        name for name, kind in contract_kinds.items()
        if kind == "interface"
    }

    def path_is_excluded_concrete_implementer(rel: str) -> bool:
        contract_names = path_contracts.get(rel, [])
        if not contract_names:
            return False
        for contract_name in contract_names:
            inherits = contract_inherits.get(contract_name, [])
            for parent in inherits:
                if parent not in interface_names:
                    continue
                concrete_bindings = concrete_bindings_by_interface.get(parent, set())
                if concrete_bindings and contract_name not in concrete_bindings:
                    return True
        return False

    def path_contains_only_interfaces(rel: str) -> bool:
        contract_names = path_contracts.get(rel, [])
        return bool(contract_names) and all(contract_kinds.get(name) == "interface" for name in contract_names)

    def add_finding(item: Dict[str, object]) -> None:
        finding_id = str(item.get("id", "")).strip()
        if not finding_id or finding_id in seen_ids:
            return
        seen_ids.add(finding_id)
        findings.append(item)

    def canonical_setters(setter_sequence: List[Dict[str, object]]) -> List[Dict[str, object]]:
        return sorted(
            [
                setter
                for setter in setter_sequence
                if isinstance(setter, dict) and str(setter.get("function", "")).strip()
            ],
            key=lambda setter: (str(setter.get("path", "")), str(setter.get("function", ""))),
        )

    def setter_sequence_names(setter_sequence: List[Dict[str, object]]) -> List[str]:
        return [
            str(setter.get("function", "")).strip()
            for setter in canonical_setters(setter_sequence)
            if str(setter.get("function", "")).strip()
        ]

    def setter_sequence_label(setter_sequence: List[Dict[str, object]]) -> str:
        return "__".join(setter_sequence_names(setter_sequence))

    rebinding_contexts: Dict[tuple[str, str], Dict[str, object]] = {}
    rebinding_pairs: set[tuple[str, str, str]] = set()
    dominated_authority_pairs: set[tuple[str, str]] = set()
    dominated_sink_targets: set[tuple[str, str]] = set()
    dominated_rebound_contracts: set[str] = set()
    rebinding_paths: set[str] = set()
    dominated_dependency_types: set[str] = set()
    dependency_shadow_map = {
        "manager": {"manager", "registry", "factory"},
        "controller": {"controller", "registry", "factory"},
        "registry": {"registry", "factory"},
        "factory": {"factory"},
    }

    def contract_slot_info(rel: str, slot_name: str) -> Dict[str, object]:
        slot_info = state_slots.get(rel, {}).get(slot_name, {})
        slot_type = str(slot_info.get("type", "")).strip()
        if not is_contract_typed(slot_type):
            return {}
        return {
            "slot": slot_name,
            "slot_type": slot_type,
            "bound_types": merge_unique(
                [str(item).strip() for item in slot_info.get("bound_types", []) if str(item).strip()]
            ),
        }

    def slot_type_name(rel: str, slot_name: str) -> str:
        return str(slot_types_by_path.get(rel, {}).get(slot_name, "")).strip()

    def branch_reads(action: Dict[str, object], rel: str) -> set[str]:
        auth_reads = guard_set(action)
        reads = set()
        for field in ("state_reads", "reads"):
            value = action.get(field)
            if isinstance(value, list):
                reads.update(
                    str(item).strip()
                    for item in value
                    if str(item).strip()
                )
        return {
            read
            for read in reads
            if read not in auth_reads and not is_contract_typed(slot_type_name(rel, read))
        }

    def relay_is_feasible(action: Dict[str, object], rel: str, controlled_slots: set[str]) -> bool:
        required_reads = branch_reads(action, rel)
        return required_reads.issubset(controlled_slots)

    def setter_is_privileged(entry: Dict[str, object]) -> bool:
        return bool(guard_set(entry))

    def apply_semantic_state(controlled_slots: set[str], semantic_function: Dict[str, object]) -> set[str]:
        explicit_true = set(semantic_true_writes(semantic_function))
        explicit_false = set(semantic_false_writes(semantic_function))
        neutral_writes = set(semantic_writes(semantic_function)) - explicit_true - explicit_false
        next_controlled = set(controlled_slots)
        next_controlled.difference_update(explicit_false)
        next_controlled.update(explicit_true | neutral_writes)
        return next_controlled

    def sequence_controlled_state(rel: str, setter_sequence: List[Dict[str, object]]) -> set[str]:
        controlled_slots: set[str] = set()
        for setter in setter_sequence:
            setter_name = str(setter.get("function", "")).strip()
            if not setter_name:
                continue
            setter_semantics = function_semantics.get((rel, setter_name), {})
            controlled_slots = apply_semantic_state(controlled_slots, setter_semantics)
        return controlled_slots

    def sequence_is_feasible(rel: str, setter_sequence: List[Dict[str, object]]) -> bool:
        controlled_slots: set[str] = set()
        for setter in setter_sequence:
            if not relay_is_feasible(setter, rel, controlled_slots):
                return False
            setter_name = str(setter.get("function", "")).strip()
            if not setter_name:
                continue
            setter_semantics = function_semantics.get((rel, setter_name), {})
            controlled_slots = apply_semantic_state(controlled_slots, setter_semantics)
        return True

    def ordered_surface_sequences_for_action(
        base_sequence: List[Dict[str, object]],
        target_action: Dict[str, object],
        controlled_slots: set[str],
        max_extra_setters: int = 2,
    ) -> List[List[Dict[str, object]]]:
        if not base_sequence:
            return []
        rel = str(base_sequence[0].get("path", ""))
        sequence_results: List[List[Dict[str, object]]] = []
        seen_sequences: set[tuple[str, ...]] = set()
        ordered_base = [
            setter
            for setter in base_sequence
            if isinstance(setter, dict) and str(setter.get("function", "")).strip()
        ]
        used_names = {
            str(setter.get("function", "")).strip()
            for setter in ordered_base
            if str(setter.get("function", "")).strip()
        }

        def record_sequence(sequence: List[Dict[str, object]]) -> None:
            key = tuple(
                str(setter.get("function", "")).strip()
                for setter in sequence
                if str(setter.get("function", "")).strip()
            )
            if not key or key in seen_sequences:
                return
            seen_sequences.add(key)
            sequence_results.append(sequence)

        def expand_sequence(
            sequence: List[Dict[str, object]],
            current_controlled: set[str],
            available_setters: List[Dict[str, object]],
            remaining_extra: int,
        ) -> None:
            if relay_is_feasible(target_action, rel, current_controlled):
                record_sequence(sequence)
            if remaining_extra <= 0:
                return
            for index, candidate in enumerate(available_setters):
                candidate_name = str(candidate.get("function", "")).strip()
                if not candidate_name:
                    continue
                candidate_semantics = function_semantics.get((rel, candidate_name), {})
                candidate_writes = set(semantic_writes(candidate_semantics))
                if not candidate_writes or not setter_is_privileged(candidate):
                    continue
                if not relay_is_feasible(candidate, rel, current_controlled):
                    continue
                next_controlled = apply_semantic_state(current_controlled, candidate_semantics)
                if next_controlled == current_controlled:
                    continue
                expand_sequence(
                    sequence + [candidate],
                    next_controlled,
                    available_setters[index + 1 :],
                    remaining_extra - 1,
                )

        candidate_setters = [
            other_setter
            for other_setter in (setters if isinstance(setters, list) else [])
            if isinstance(other_setter, dict)
            and str(other_setter.get("path", "")) == rel
            and str(other_setter.get("function", "")).strip()
            and str(other_setter.get("function", "")).strip() not in used_names
        ]
        expand_sequence(ordered_base, set(controlled_slots), candidate_setters, max_extra_setters)
        return sequence_results

    def consumer_actions_for_slot(rel: str, slot_name: str) -> List[Dict[str, object]]:
        consumers: List[Dict[str, object]] = []
        for action in actions:
            if not isinstance(action, dict) or str(action.get("path", "")) != rel:
                continue
            action_name = str(action.get("function", ""))
            action_semantics = function_semantics.get((rel, action_name), {})
            member_calls = action_semantics.get("member_calls", []) if isinstance(action_semantics.get("member_calls"), list) else []
            matching_member_calls = [
                call for call in member_calls
                if isinstance(call, dict) and str(call.get("receiver", "")).strip() == slot_name
            ]
            if matching_member_calls:
                consumers.append({**action, "member_calls": matching_member_calls})
                continue
            action_reads = {
                str(item).strip()
                for item in action.get("state_reads", [])
                if str(item).strip()
            } if isinstance(action.get("state_reads"), list) else set()
            if slot_name not in action_reads:
                continue
            action_writes = semantic_writes(action_semantics)
            if any(contract_slot_info(rel, written_slot) for written_slot in action_writes if written_slot != slot_name):
                consumers.append({**action, "member_calls": []})
        return consumers

    def implementers_for_type(type_name: str) -> List[str]:
        if not type_name:
            return []
        return sorted(
            contract_name
            for contract_name, inherits in contract_inherits.items()
            if type_name in inherits
        )

    def relay_bound_types(action: Dict[str, object]) -> List[str]:
        return merge_unique(
            [
                str(item).strip()
                for item in action.get("internal_calls", [])
                if is_contract_typed(item)
            ] if isinstance(action.get("internal_calls"), list) else []
        )

    def contract_function_guards(contract_name: str, function_name: str) -> set[str]:
        function = contract_functions.get(contract_name, {}).get(function_name, {})
        if not isinstance(function, dict):
            return set()
        return guard_set(function)

    def rebound_surface_diverges(bound_types: List[str], sink_name: str, relay_actions: List[Dict[str, object]] | None = None) -> bool:
        guard_profiles = {
            tuple(sorted(contract_function_guards(bound_type, sink_name)))
            for bound_type in bound_types
            if bound_type in contract_paths and contract_kinds.get(bound_type) != "interface"
        }
        if not guard_profiles:
            return bool(relay_actions) or len(set(bound_types)) > 1
        return len(guard_profiles) > 1

    def add_rebinding_finding(
        setter_sequence: List[Dict[str, object]],
        origin_slot: str,
        slot_name: str,
        slot_type: str,
        bound_types: List[str],
        consumers: List[Dict[str, object]],
        relay_actions: List[Dict[str, object]] | None = None,
        rebound_slot: str = "",
    ) -> None:
        sink_consumers = [consumer for consumer in consumers if consumer.get("sink_hints")]
        if not sink_consumers:
            return
        relay_actions = relay_actions or []
        best_sink = sorted(
            sink_consumers,
            key=lambda item: (
                -len(item.get("sink_hints", [])),
                -len(item.get("external_calls", [])),
                str(item.get("function", "")),
            ),
        )[0]
        sink_name = str(best_sink.get("function", "")).strip()
        implementation_sink_name = next(
            (
                str(call.get("function", "")).strip()
                for call in best_sink.get("member_calls", [])
                if isinstance(call, dict)
                and str(call.get("receiver", "")).strip() == slot_name
                and str(call.get("function", "")).strip()
            ),
            sink_name,
        )
        if implementation_sink_name and not rebound_surface_diverges(bound_types, implementation_sink_name, relay_actions):
            return
        ordered_setters = canonical_setters(setter_sequence)
        if not ordered_setters:
            return
        primary_setter = ordered_setters[0]
        setter_names = setter_sequence_names(ordered_setters)
        setter_label = setter_sequence_label(ordered_setters)
        setter_guards = set.intersection(*(guard_set(setter) for setter in ordered_setters)) if ordered_setters else set()
        sink_guards = guard_set(best_sink)
        confidence = 0.92
        if setter_guards == sink_guards:
            confidence -= 0.05
        if len(bound_types) < 2:
            confidence -= 0.05
        if relay_actions:
            confidence -= min(0.08, 0.03 * len(relay_actions))
        if len(ordered_setters) > 1:
            confidence -= min(0.04, 0.02 * (len(ordered_setters) - 1))
        evidence_entry: Dict[str, object] = {
            "setters": ordered_setters,
            "origin_slot": origin_slot,
            "slot": slot_name,
            "slot_type": slot_type,
            "bound_types": bound_types,
            "sink": best_sink,
            "consumers": [
                {
                    "function": consumer.get("function", ""),
                    "sink_hints": consumer.get("sink_hints", []),
                    "state_keywords": consumer.get("state_keywords", []),
                }
                for consumer in consumers[:6]
            ],
        }
        if relay_actions and rebound_slot:
            evidence_entry["relay_actions"] = [
                {
                    "function": relay_action.get("function", ""),
                    "writes": relay_action.get("writes", []),
                    "member_calls": relay_action.get("member_calls", []),
                }
                for relay_action in relay_actions[:4]
            ]
            evidence_entry["rebound_slot"] = rebound_slot
        finding = {
            "id": f"implementation-rebinding-{setter_label}-{best_sink.get('function', 'unknown')}",
            "family": "implementation_rebinding",
            "title": (
                f"Implementation rebinding through {' and '.join(setter_names)} "
                f"can reshape the authority surface behind {best_sink.get('function', 'unknown')}"
            ),
            "target_contract": primary_setter.get("path", ""),
            "target_functions": merge_unique(
                [
                    *setter_names,
                    *[
                        str(relay_action.get("function", ""))
                        for relay_action in relay_actions
                        if str(relay_action.get("function", "")).strip()
                    ],
                    str(best_sink.get("function", "")),
                ]
            ),
            "violated_invariant": "Implementation rewiring should not let privileged configuration swap the reachable authority or settlement surface behind live actions.",
            "evidence": [evidence_entry],
            "confidence_score": confidence,
            "blocking_unknowns": [
                "Need source review to confirm the rebound implementation actually weakens the reachable guard surface.",
            ],
        }
        add_finding(finding)
        context_slot = rebound_slot or slot_name
        rel = str(primary_setter.get("path", ""))
        sink_name = str(best_sink.get("function", "")).strip()
        for setter_name in setter_names:
            setter_lower = setter_name.lower()
            for dependency_type in ("registry", "controller", "factory", "manager"):
                if dependency_type in setter_lower:
                    dominated_dependency_types.update(dependency_shadow_map.get(dependency_type, {dependency_type}))
        if sink_name:
            dominated_sink_targets.add((rel, sink_name))
        dominated_rebound_contracts.update(
            contract_name
            for contract_name in bound_types
            if contract_name in contract_kinds
        )
        rebinding_paths.add(rel)
        rebinding_contexts[(rel, context_slot)] = {
            "sink_functions": {sink_name},
            "consumer_functions": {
                str(consumer.get("function", ""))
                for consumer in consumers
                if str(consumer.get("function", "")).strip()
            },
        }
        for consumer in consumers:
            consumer_name = str(consumer.get("function", "")).strip()
            if consumer_name and sink_name and consumer_name != sink_name:
                rebinding_pairs.add((rel, consumer_name, sink_name))
                dominated_authority_pairs.add((consumer_name, sink_name))

    def slot_bound_types(rel: str, slot_name: str, consumers: List[Dict[str, object]]) -> List[str]:
        slot_info = contract_slot_info(rel, slot_name)
        if not slot_info:
            return []
        slot_type = str(slot_info.get("slot_type", "")).strip()
        slot_bound_types = [
            str(item).strip()
            for item in slot_info.get("bound_types", [])
            if str(item).strip()
        ]
        member_call_bound_types = [
            str(bound).strip()
            for consumer in consumers
            for call in consumer.get("member_calls", [])
            if isinstance(call, dict)
            for bound in call.get("bound_types", [])
            if str(bound).strip()
        ]
        concrete_bound_types = [
            bound_type
            for bound_type in (slot_bound_types + member_call_bound_types)
            if bound_type and bound_type != slot_type
        ]
        return merge_unique(
            [
                *slot_bound_types,
                slot_type,
                *([] if concrete_bound_types else implementers_for_type(slot_type)),
                *member_call_bound_types,
            ]
        )

    def concrete_bound_types(bound_types: List[str], slot_type: str) -> List[str]:
        return [
            bound_type
            for bound_type in bound_types
            if bound_type
            and bound_type != slot_type
            and contract_kinds.get(bound_type) != "interface"
        ]

    def reconcile_bound_types(slot_type: str, inherited_bound_types: List[str], inferred_bound_types: List[str]) -> List[str]:
        inherited = merge_unique(inherited_bound_types)
        inferred = merge_unique(inferred_bound_types)
        if not inherited:
            return inferred
        inherited_concrete = set(concrete_bound_types(inherited, slot_type))
        if not inherited_concrete:
            return merge_unique(inherited + inferred)
        filtered_inferred = [
            bound_type
            for bound_type in inferred
            if bound_type == slot_type
            or contract_kinds.get(bound_type) == "interface"
            or bound_type in inherited_concrete
        ]
        return merge_unique(inherited + filtered_inferred)

    def relay_specific_bound_types(
        slot_name: str,
        slot_type: str,
        inherited_bound_types: List[str],
        relay_action: Dict[str, object],
    ) -> List[str]:
        relay_member_bound_types = merge_unique(
            [
                str(bound_type).strip()
                for call in relay_action.get("member_calls", [])
                if isinstance(call, dict) and str(call.get("receiver", "")).strip() == slot_name
                for bound_type in call.get("bound_types", [])
                if str(bound_type).strip()
            ]
        )
        if not relay_member_bound_types:
            return merge_unique(inherited_bound_types)
        return reconcile_bound_types(
            slot_type,
            inherited_bound_types,
            relay_member_bound_types,
        )

    def walk_rebinding_paths(
        setter_sequence: List[Dict[str, object]],
        origin_slot: str,
        current_slot: str,
        inherited_bound_types: List[str],
        relay_actions: List[Dict[str, object]],
        visited_slots: set[str],
        controlled_slots: set[str],
    ) -> None:
        ordered_setters = canonical_setters(setter_sequence)
        if not ordered_setters:
            return
        primary_setter = ordered_setters[0]
        rel = str(primary_setter.get("path", ""))
        consumers = consumer_actions_for_slot(rel, current_slot)
        if not consumers:
            return
        current_slot_type = str(contract_slot_info(rel, current_slot).get("slot_type", ""))
        inferred_slot_bound_types = slot_bound_types(rel, current_slot, consumers)
        current_bound_types = merge_unique(inherited_bound_types + inferred_slot_bound_types)
        add_rebinding_finding(
            ordered_setters,
            origin_slot,
            current_slot,
            current_slot_type,
            current_bound_types,
            consumers,
            relay_actions=relay_actions,
            rebound_slot=current_slot if current_slot != origin_slot else "",
        )
        if len(relay_actions) >= MAX_REBINDING_RELAY_DEPTH:
            return
        for relay_action in consumers:
            relay_name = str(relay_action.get("function", "")).strip()
            setter_names = set(setter_sequence_names(ordered_setters))
            if not relay_name or relay_name in setter_names:
                continue
            candidate_sequences = ordered_surface_sequences_for_action(
                ordered_setters,
                relay_action,
                controlled_slots,
            )
            for candidate_sequence in candidate_sequences:
                candidate_controlled = sequence_controlled_state(rel, candidate_sequence)
                if not relay_is_feasible(relay_action, rel, candidate_controlled):
                    continue
                relay_semantics = function_semantics.get((rel, relay_name), {})
                relay_writes = semantic_writes(relay_semantics)
                rebound_slots = [
                    rebound_slot
                    for rebound_slot in relay_writes
                    if rebound_slot != current_slot and rebound_slot not in visited_slots and contract_slot_info(rel, rebound_slot)
                ]
                relay_path_bound_types = relay_specific_bound_types(
                    current_slot,
                    current_slot_type,
                    current_bound_types,
                    relay_action,
                )
                for rebound_slot in rebound_slots:
                    next_consumers = consumer_actions_for_slot(rel, rebound_slot)
                    rebound_candidates = relay_bound_types(relay_action)
                    rebound_slot_type = str(contract_slot_info(rel, rebound_slot).get("slot_type", ""))
                    inferred_rebound_types = slot_bound_types(rel, rebound_slot, next_consumers)
                    next_bound_types = reconcile_bound_types(
                        rebound_slot_type,
                        rebound_candidates if rebound_candidates else relay_path_bound_types,
                        inferred_rebound_types,
                    )
                    walk_rebinding_paths(
                        candidate_sequence,
                        origin_slot,
                        rebound_slot,
                        next_bound_types,
                        relay_actions + [relay_action],
                        visited_slots | {rebound_slot},
                        apply_semantic_state(candidate_controlled, relay_semantics) | {current_slot, rebound_slot},
                    )

    def compatible_setter_sequences(setter: Dict[str, object], semantic_function: Dict[str, object]) -> List[List[Dict[str, object]]]:
        rel = str(setter.get("path", ""))
        setter_name = str(setter.get("function", "")).strip()
        if not setter_name:
            return []
        setter_guard_profile = guard_set(setter)
        compatible: List[Dict[str, object]] = []
        for other_setter in setters if isinstance(setters, list) else []:
            if not isinstance(other_setter, dict):
                continue
            other_rel = str(other_setter.get("path", ""))
            other_name = str(other_setter.get("function", "")).strip()
            if other_rel != rel or not other_name or other_name == setter_name:
                continue
            other_semantics = function_semantics.get((other_rel, other_name), {})
            if not semantic_writes(other_semantics):
                continue
            if guard_set(other_setter) != setter_guard_profile:
                continue
            compatible.append(other_setter)
        sequences: List[List[Dict[str, object]]] = [[setter]]
        for extra_count in (1, 2):
            for extra_setters in combinations(compatible, extra_count):
                sequences.append(canonical_setters([setter, *extra_setters]))
        return sequences

    if isinstance(setters, list):
        for setter in setters:
            if not isinstance(setter, dict):
                continue
            rel = str(setter.get("path", ""))
            setter_name = str(setter.get("function", ""))
            semantic_function = function_semantics.get((rel, setter_name), {})
            direct_writes = semantic_writes(semantic_function)
            if not direct_writes:
                continue
            for setter_sequence in compatible_setter_sequences(setter, semantic_function):
                if not sequence_is_feasible(rel, setter_sequence):
                    continue
                sequence_names = {str(item.get("function", "")).strip() for item in setter_sequence if isinstance(item, dict)}
                sequence_writes = sequence_controlled_state(rel, setter_sequence)
                for slot_name in sequence_writes:
                    contract_slot = contract_slot_info(rel, slot_name)
                    if contract_slot:
                        direct_consumers = consumer_actions_for_slot(rel, slot_name)
                        direct_bound_types = slot_bound_types(rel, slot_name, direct_consumers)
                        slot_type = str(contract_slot.get("slot_type", "")).strip()
                        setter_param_types = parse_param_types(semantic_function.get("params", ""))
                        setter_origin_candidates = relay_bound_types(setter)
                        if slot_type and slot_type in setter_param_types:
                            setter_origin_candidates = merge_unique(
                                setter_origin_candidates + implementers_for_type(slot_type)
                            )
                        if setter_origin_candidates:
                            direct_bound_types = merge_unique(direct_bound_types + setter_origin_candidates)
                        concrete_origin_types = {
                            bound_type
                            for bound_type in direct_bound_types
                            if bound_type and bound_type != slot_type
                        }
                        setter_accepts_abstract_slot = bool(slot_type) and slot_type in setter_param_types
                        if (
                            contract_kinds.get(slot_type) == "interface"
                            and not setter_accepts_abstract_slot
                            and len(concrete_origin_types) <= 1
                        ):
                            continue
                        walk_rebinding_paths(
                            setter_sequence,
                            slot_name,
                            slot_name,
                            direct_bound_types,
                            [],
                            {slot_name},
                            set(sequence_writes),
                        )
                        continue
                    relay_actions = [
                        action
                        for action in actions
                        if isinstance(action, dict)
                        and str(action.get("path", "")) == rel
                        and str(action.get("function", "")).strip() not in sequence_names
                        and slot_name in {
                            str(item).strip()
                            for item in action.get("state_reads", [])
                            if str(item).strip()
                        }
                    ]
                    for relay_action in relay_actions:
                        relay_name = str(relay_action.get("function", "")).strip()
                        candidate_sequences = ordered_surface_sequences_for_action(
                            setter_sequence,
                            relay_action,
                            set(sequence_writes),
                        )
                        for candidate_sequence in candidate_sequences:
                            candidate_controlled = sequence_controlled_state(rel, candidate_sequence)
                            if not relay_is_feasible(relay_action, rel, candidate_controlled):
                                continue
                            relay_semantics = function_semantics.get((rel, relay_name), {})
                            relay_writes = semantic_writes(relay_semantics)
                            for rebound_slot in relay_writes:
                                rebound_contract_slot = contract_slot_info(rel, rebound_slot)
                                if not rebound_contract_slot:
                                    continue
                                next_consumers = consumer_actions_for_slot(rel, rebound_slot)
                                rebound_candidates = relay_bound_types(relay_action)
                                rebound_slot_type = str(rebound_contract_slot.get("slot_type", ""))
                                inferred_rebound_types = slot_bound_types(rel, rebound_slot, next_consumers)
                                next_bound_types = reconcile_bound_types(
                                    rebound_slot_type,
                                    rebound_candidates,
                                    inferred_rebound_types,
                                )
                                walk_rebinding_paths(
                                    candidate_sequence,
                                    slot_name,
                                    rebound_slot,
                                    next_bound_types,
                                    [relay_action],
                                    {rebound_slot},
                                    apply_semantic_state(candidate_controlled, relay_semantics) | {rebound_slot},
                                )

    if isinstance(sinks, list):
        for sink in sinks:
            sink_rel = str(sink.get("path", ""))
            sink_name = str(sink.get("function", ""))
            if (
                isinstance(sink, dict)
                and (sink_rel, sink_name) not in dominated_sink_targets
                and not any(contract_name in dominated_rebound_contracts for contract_name in path_contracts.get(sink_rel, []))
                and not sink.get("guards")
                and sink.get("writes")
                and not any(keyword in sink.get("state_keywords", []) for keyword in ("settle", "redeem", "claim", "close", "recover"))
            ):
                add_finding(
                    {
                        "id": f"unguarded-sink-{sink.get('function', 'unknown')}",
                        "family": "authority_drift",
                        "title": f"Sensitive sink {sink.get('function', 'unknown')} lacks an explicit guard",
                        "target_contract": sink.get("path", ""),
                        "target_functions": [sink.get("function", "")],
                        "violated_invariant": "Sensitive sinks should have an explicit authority boundary.",
                        "evidence": [sink],
                        "confidence_score": 0.7,
                        "blocking_unknowns": [],
                    }
                )

    if isinstance(setters, list) and isinstance(sinks, list):
        for setter in setters:
            if not isinstance(setter, dict):
                continue
            setter_writes = set(str(item) for item in setter.get("writes", []) if item)
            setter_reads = set(str(item) for item in setter.get("reads", []) if item)
            if not setter_writes:
                continue
            for sink in sinks:
                if not isinstance(sink, dict):
                    continue
                sink_writes = set(str(item) for item in sink.get("writes", []) if item)
                sink_reads = set(str(item) for item in sink.get("reads", []) if item)
                if not sink_writes:
                    continue
                setter_rel = str(setter.get("path", ""))
                sink_rel = str(sink.get("path", ""))
                if setter_rel != sink_rel:
                    continue
                if path_is_excluded_concrete_implementer(setter_rel):
                    continue
                setter_name = str(setter.get("function", ""))
                sink_name = str(sink.get("function", ""))
                setter_semantics = function_semantics.get((setter_rel, setter_name), {})
                sink_semantics = function_semantics.get((setter_rel, sink_name), {})
                if (setter_rel, setter_name, sink_name) in rebinding_pairs:
                    continue
                if (setter_name, sink_name) in dominated_authority_pairs:
                    continue
                setter_receivers = {
                    str(call.get("receiver", "")).strip()
                    for call in setter_semantics.get("member_calls", [])
                    if isinstance(call, dict) and str(call.get("receiver", "")).strip()
                } if isinstance(setter_semantics.get("member_calls"), list) else set()
                sink_receivers = {
                    str(call.get("receiver", "")).strip()
                    for call in sink_semantics.get("member_calls", [])
                    if isinstance(call, dict) and str(call.get("receiver", "")).strip()
                } if isinstance(sink_semantics.get("member_calls"), list) else set()
                if any(
                    context
                    and sink_name in context.get("sink_functions", set())
                    and setter_name in context.get("consumer_functions", set())
                    for receiver in (setter_receivers | sink_receivers)
                    for context in [rebinding_contexts.get((setter_rel, receiver))]
                ):
                    continue
                if any(
                    context and sink_name in context.get("sink_functions", set()) and setter_name in context.get("consumer_functions", set())
                    for receiver in (setter_receivers & sink_receivers)
                    for context in [rebinding_contexts.get((setter_rel, receiver))]
                ):
                    continue
                overlap = sorted((setter_writes & sink_writes) | (setter_writes & sink_reads) | (sink_writes & setter_reads))
                if not overlap:
                    continue
                setter_guards = guard_set(setter)
                sink_guards = guard_set(sink)
                if setter_guards != sink_guards:
                    add_finding(
                        {
                            "id": f"authority-drift-{setter.get('function', 'unknown')}-{sink.get('function', 'unknown')}",
                            "family": "authority_drift",
                            "title": f"Authority-linked setter {setter.get('function', 'unknown')} and sink {sink.get('function', 'unknown')} drift on shared state",
                            "target_contract": sink.get("path", ""),
                            "target_functions": [setter.get("function", ""), sink.get("function", "")],
                            "violated_invariant": "Administrative transitions should not let setter and sink authority drift apart on shared state.",
                            "evidence": [{"setter": setter, "sink": sink, "shared_writes": overlap}],
                            "confidence_score": 0.8,
                            "blocking_unknowns": ["Need source review to confirm the shared state is security-sensitive and reachable."],
                        }
                    )

    if isinstance(dependencies, list):
        for dep in dependencies:
            if not isinstance(dep, dict):
                continue
            dep_rel = str(dep.get("path", ""))
            dep_type = str(dep.get("type", "unknown"))
            dep_criticality = str(dep.get("criticality", "informational"))
            if dep_criticality == "recovery_critical":
                if dep_type in dominated_dependency_types:
                    continue
                related_recovery_actions = [
                    action for action in actions
                    if isinstance(action, dict)
                    and action.get("path") == dep.get("path")
                    and any(keyword in action.get("state_keywords", []) for keyword in ("recover", "rotate", "close"))
                ] if isinstance(actions, list) else []
                if path_contains_only_interfaces(dep_rel) and not related_recovery_actions:
                    continue
                if dep_rel in rebinding_paths and dep_type in {"registry", "controller", "factory", "manager"}:
                    continue
                if any(contract_name in dominated_rebound_contracts for contract_name in path_contracts.get(dep_rel, [])):
                    continue
                if not related_recovery_actions and dep_rel in rebinding_paths:
                    continue
                add_finding(
                    {
                        "id": f"recovery-dependency-{dep.get('type', 'unknown')}",
                        "family": "dependency_recovery_lockup",
                        "title": f"Recovery may depend on non-rotatable {dep_type} behavior",
                        "target_contract": dep.get("path", ""),
                        "target_functions": [str(action.get("function", "")) for action in related_recovery_actions[:3]],
                        "violated_invariant": "Recovery-critical dependencies should have a fallback or rotation path.",
                        "evidence": [dep] + related_recovery_actions[:2],
                        "confidence_score": 0.65 if related_recovery_actions else 0.5,
                        "blocking_unknowns": ["Need exact rotation or fallback path confirmation."] if related_recovery_actions else ["Need repo-backed recovery action evidence."],
                    }
                )
            elif dep_criticality == "settlement_critical":
                related_settlement_actions = [
                    action for action in actions
                    if isinstance(action, dict)
                    and action.get("path") == dep.get("path")
                    and any(keyword in action.get("state_keywords", []) for keyword in ("settle", "redeem", "claim", "close"))
                ] if isinstance(actions, list) else []
                if related_settlement_actions:
                    settlement_reads_state = any(action.get("state_reads") for action in related_settlement_actions if isinstance(action, dict))
                    add_finding(
                        {
                            "id": f"settlement-dependency-{dep_type}",
                            "family": "settlement_dependency_drift",
                            "title": f"Settlement may depend on fragile {dep_type} behavior",
                            "target_contract": dep.get("path", ""),
                            "target_functions": [str(action.get("function", "")) for action in related_settlement_actions[:3]],
                            "violated_invariant": "Settlement-critical dependencies should fail closed on stale or manipulated responses.",
                            "evidence": [dep] + related_settlement_actions[:2],
                            "confidence_score": 0.8 if settlement_reads_state else 0.75,
                            "blocking_unknowns": ["Need source review for stale-response handling, fallback logic, and settlement ordering."],
                        }
                    )

    for action in actions:
        if not isinstance(action, dict):
            continue
        action_path = str(action.get("path", ""))
        if any(contract_name in dominated_rebound_contracts for contract_name in path_contracts.get(action_path, [])):
            continue
        action_name = str(action.get("function", "")).strip()
        action_semantics = function_semantics.get((action_path, action_name), {})
        member_calls = action_semantics.get("member_calls", []) if isinstance(action_semantics.get("member_calls"), list) else []
        direct_writes = action_semantics.get("writes", []) if isinstance(action_semantics.get("writes"), list) else []
        direct_external_calls = action_semantics.get("external_calls", []) if isinstance(action_semantics.get("external_calls"), list) else []
        if any(
            (
                rebinding_contexts.get((action_path, str(call.get("receiver", "")).strip()))
                or any(
                    str(bound_type).strip() in dominated_rebound_contracts
                    for bound_type in call.get("bound_types", [])
                    if str(bound_type).strip()
                )
            )
            for call in member_calls
            if isinstance(call, dict) and str(call.get("receiver", "")).strip()
        ):
            continue
        if member_calls and not direct_writes and not direct_external_calls:
            continue
        material_writes = {
            str(item).strip()
            for item in action.get("writes", [])
            if str(item).strip() and str(item).strip() != "sender"
        } if isinstance(action.get("writes"), list) else set()
        if action.get("external_calls") and action.get("writes") and action.get("visibility") in {"external", "public"}:
            if not material_writes:
                continue
            confidence_score = 0.68 if action.get("state_reads") else 0.62
            if action.get("auth_guards"):
                confidence_score -= 0.1
            add_finding(
                {
                    "id": f"callback-state-drift-{action.get('function', 'unknown')}",
                    "family": "callback_state_drift",
                    "title": f"External call in {action.get('function', 'unknown')} may expose stateful invariant drift",
                    "target_contract": action.get("path", ""),
                    "target_functions": [action.get("function", "")],
                    "violated_invariant": "State-changing flows should remain safe when external control is yielded.",
                    "evidence": [action],
                    "confidence_score": confidence_score,
                    "blocking_unknowns": ["Need source review for effect ordering and reentry surface."],
                }
            )
        if any(keyword in action.get("state_keywords", []) for keyword in ("settle", "recover", "close")):
            add_finding(
                {
                    "id": f"recovery-path-{action.get('function', 'unknown')}",
                    "family": "broken_recovery",
                    "title": f"{action.get('function', 'unknown')} should remain reachable in degraded states",
                    "target_contract": action.get("path", ""),
                    "target_functions": [action.get("function", "")],
                    "violated_invariant": "Recovery and settlement paths should remain reachable after failure states.",
                    "evidence": [action],
                    "confidence_score": 0.5,
                    "blocking_unknowns": ["Need exact failure mode and fallback-path confirmation."],
                }
            )
        if (
            any(keyword in action.get("state_keywords", []) for keyword in ("rotate",))
            and not action.get("auth_guards")
            and (
                action.get("external_calls")
                or action.get("trust_boundary")
            )
        ):
            add_finding(
                {
                    "id": f"unguarded-rotation-{action.get('function', 'unknown')}",
                    "family": "authority_drift",
                    "title": f"Rotation path {action.get('function', 'unknown')} lacks a clear guard",
                    "target_contract": action.get("path", ""),
                    "target_functions": [action.get("function", "")],
                    "violated_invariant": "Security-relevant rotation paths should be explicitly guarded.",
                    "evidence": [action],
                    "confidence_score": 0.7,
                    "blocking_unknowns": [],
                }
            )

    # Item 12: add contradiction-backed candidates from invariant analysis
    if isinstance(invariant_entries, list) and isinstance(semantic_files, list):
        contradiction_candidates = _build_contradiction_candidates(invariant_entries, semantic_files)
        for cand in contradiction_candidates:
            cand_id = str(cand.get("id", ""))
            if cand_id not in seen_ids:
                findings.append(cand)
                seen_ids.add(cand_id)

    findings = sorted(
        findings,
        key=lambda item: (
            -float(item.get("confidence_score", 0.0)),
            str(item.get("family", "")),
            str(item.get("id", "")),
        ),
    )

    write_text(Path(artifacts["finding_candidates"]), json.dumps({"findings": findings}, indent=2, sort_keys=True) + "\n")
    status = PhaseStatus(
        phase="finding_candidates",
        ok=True,
        mode="full",
        artifacts=artifacts,
        warnings=[] if findings else ["No finding candidates were generated for this target."],
        errors=[],
        details={
            "target_dir": args.target_dir,
            "finding_count": len(findings),
            "invariant_count": len(invariant_entries) if isinstance(invariant_entries, list) else 0,
        },
    )
    return finalize(status)


if __name__ == "__main__":
    raise SystemExit(main())
