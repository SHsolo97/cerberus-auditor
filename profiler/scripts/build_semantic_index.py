from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List

from common import AUDIT_DIR, PhaseStatus, discover_solidity_files, finalize, make_failure_status, write_text


CONTRACT_RE = re.compile(r"\b(contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)\b")
CONTRACT_HEADER_RE = re.compile(
    r"\b(contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s+is\s+([^{}]+))?\s*\{",
    re.MULTILINE,
)
FUNCTION_RE = re.compile(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)([^{};]*)\{", re.MULTILINE)
CONSTRUCTOR_RE = re.compile(r"\bconstructor\s*\(([^)]*)\)([^{};]*)\{", re.MULTILINE)
STATE_RE = re.compile(r"\b(address|uint256|uint128|uint64|bool|bytes32|string)\s+(?:public|private|internal|external)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*;")
CUSTOM_STATE_RE = re.compile(r"\b([A-Z][A-Za-z0-9_]*)\s+(?:public|private|internal|external)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*;")
ROLE_CONST_RE = re.compile(r"\b([A-Z][A-Z0-9_]*_ROLE)\b")
ROLE_GUARD_RE = re.compile(r"onlyRole\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)")
OWNER_GUARD_RE = re.compile(r"onlyOwner|owner\s*==\s*msg\.sender|msg\.sender\s*==\s*owner")
EXTERNAL_CALL_RE = re.compile(r"\.(call|delegatecall|staticcall|transfer|transferFrom|safeTransfer|safeTransferFrom)\b")
WRITE_HINT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\+?=|\-?=|\*=|/=|%=)")
BOOL_TRUE_ASSIGN_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*true\s*;")
BOOL_FALSE_ASSIGN_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*false\s*;")
REQUIRE_RE = re.compile(r"require\s*\(([^;]+?)\)\s*;")
MSG_SENDER_REQUIRE_RE = re.compile(r"msg\.sender\s*==\s*([A-Za-z_][A-Za-z0-9_]*)|([A-Za-z_][A-Za-z0-9_]*)\s*==\s*msg\.sender")
WORD_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")
INTERNAL_CALL_RE = re.compile(r"(?<!\.)\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
MEMBER_CALL_RE = re.compile(r"\b([a-z_][A-Za-z0-9_]*)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(")
NEW_ASSIGN_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+([A-Z][A-Za-z0-9_]*)\s*\(")
CAST_NEW_ASSIGN_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[A-Z][A-Za-z0-9_]*\s*\([^;]*?new\s+([A-Z][A-Za-z0-9_]*)\s*\(",
    re.DOTALL,
)
ASSIGN_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(")
ASSIGN_PARAM_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*;")
MEMBER_ASSIGN_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([a-z_][A-Za-z0-9_]*)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(")
RETURN_NEW_RE = re.compile(r"\breturn\s+new\s+([A-Z][A-Za-z0-9_]*)\s*\(")
SINK_HINTS = ("withdraw", "rescue", "claim", "sweep", "execute", "upgrade", "mint", "burn", "transfer")
STATE_KEYWORDS = ("settle", "recover", "close", "rotate", "pause", "redeem", "claim", "liquidate")
CALL_KEYWORDS = {
    "if", "for", "while", "require", "assert", "revert", "return",
    "emit", "abi", "keccak256", "super", "mapping", "new"
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a semantic index for Solidity sources.")
    parser.add_argument("--target-dir", required=True, help="Directory containing Solidity contracts.")
    return parser.parse_args()


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def function_body(text: str, body_start: int) -> str:
    depth = 1
    index = body_start
    while index < len(text):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return text[body_start:index]
        index += 1
    return text[body_start:]


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def block_end(text: str, body_start: int) -> int:
    depth = 1
    index = body_start
    while index < len(text):
        char = text[index]
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
        index += 1
    return len(text)


def parse_param_types(params: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for raw_param in params.split(","):
        raw = raw_param.strip()
        if not raw:
            continue
        tokens = [token for token in raw.split() if token not in {"memory", "calldata", "storage", "payable"}]
        if len(tokens) < 2:
            continue
        param_name = tokens[-1].strip()
        param_type = tokens[-2].strip()
        if param_name and param_type:
            result[param_name] = param_type
    return result


def match_params(match: re.Match[str]) -> str:
    groups = match.groups()
    if len(groups) >= 3:
        return str(groups[1])
    if groups:
        return str(groups[0])
    return ""


def owner_contract_name(offset: int, contract_blocks: List[Dict[str, object]]) -> str:
    for block in contract_blocks:
        start = int(block.get("start", -1))
        end = int(block.get("end", -1))
        if start <= offset <= end:
            return str(block.get("name", "")).strip()
    return ""


def main() -> int:
    args = parse_args()
    target_dir = Path(args.target_dir).resolve()
    artifacts = {"semantic_index": str(AUDIT_DIR / "semantic_index.json")}

    if not target_dir.exists() or not target_dir.is_dir():
        return finalize(
            make_failure_status("semantic_index", errors=[f"Target directory does not exist: {target_dir}"], artifacts=artifacts)
        )

    files = discover_solidity_files(target_dir)
    if not files:
        return finalize(
            make_failure_status("semantic_index", errors=[f"No Solidity files found under: {target_dir}"], artifacts=artifacts)
        )

    contracts: List[Dict[str, object]] = []
    file_entries: List[Dict[str, object]] = []
    for path in files:
        text = read_text(path)
        rel = path.relative_to(target_dir.parent).as_posix()
        contract_hits = []
        contract_blocks: List[Dict[str, object]] = []
        for match in CONTRACT_HEADER_RE.finditer(text):
            kind = match.group(1)
            name = match.group(2)
            parents = match.group(3)
            inherits = [
                token.strip()
                for token in parents.split(",")
                if token.strip()
            ] if parents else []
            end = block_end(text, match.end())
            contract_hits.append({"kind": kind, "name": name, "inherits": inherits})
            contract_blocks.append(
                {
                    "kind": kind,
                    "name": name,
                    "inherits": inherits,
                    "start": match.start(),
                    "end": end,
                }
            )
        if not contract_hits:
            contract_hits = [{"kind": kind, "name": name, "inherits": []} for kind, name in CONTRACT_RE.findall(text)]
        primitive_state_vars = [{"type": typ, "name": name} for typ, name in STATE_RE.findall(text)]
        custom_state_vars = [
            {"type": typ, "name": name}
            for typ, name in CUSTOM_STATE_RE.findall(text)
            if typ not in {"contract", "interface", "library"}
        ]
        state_vars: List[Dict[str, object]] = []
        seen_state_names: set[str] = set()
        for match in STATE_RE.finditer(text):
            name = match.group(2)
            if name in seen_state_names:
                continue
            seen_state_names.add(name)
            state_vars.append(
                {
                    "type": match.group(1),
                    "name": name,
                    "contract": owner_contract_name(match.start(), contract_blocks),
                }
            )
        for match in CUSTOM_STATE_RE.finditer(text):
            typ = match.group(1)
            name = match.group(2)
            if typ in {"contract", "interface", "library"} or name in seen_state_names:
                continue
            seen_state_names.add(name)
            state_vars.append(
                {
                    "type": typ,
                    "name": name,
                    "contract": owner_contract_name(match.start(), contract_blocks),
                }
            )
        state_var_names = {entry["name"] for entry in state_vars}
        state_var_types = {entry["name"]: entry["type"] for entry in state_vars}
        role_constants = sorted(set(ROLE_CONST_RE.findall(text)))
        helper_return_types: Dict[str, List[str]] = {}
        function_matches = list(FUNCTION_RE.finditer(text))
        constructor_matches = list(CONSTRUCTOR_RE.finditer(text))
        for match in function_matches:
            name = match.group(1)
            body = function_body(text, match.end())
            return_new_types = [
                bound_type
                for bound_type in RETURN_NEW_RE.findall(body)
                if bound_type.strip()
            ]
            if return_new_types:
                helper_return_types[name] = sorted(set(return_new_types))

        state_bindings: Dict[str, List[str]] = {}
        for receiver, bound_type in NEW_ASSIGN_RE.findall(text):
            if receiver not in state_var_types:
                continue
            state_bindings.setdefault(receiver, [])
            if bound_type not in state_bindings[receiver]:
                state_bindings[receiver].append(bound_type)
        for receiver, bound_type in CAST_NEW_ASSIGN_RE.findall(text):
            if receiver not in state_var_types:
                continue
            state_bindings.setdefault(receiver, [])
            if bound_type not in state_bindings[receiver]:
                state_bindings[receiver].append(bound_type)
        for match in function_matches:
            body = function_body(text, match.end())
            for receiver, callee_name in ASSIGN_CALL_RE.findall(body):
                if receiver not in state_var_types:
                    continue
                for bound_type in helper_return_types.get(callee_name, []):
                    state_bindings.setdefault(receiver, [])
                    if bound_type not in state_bindings[receiver]:
                        state_bindings[receiver].append(bound_type)
        binding_matches = constructor_matches + function_matches
        for match in binding_matches:
            params = match_params(match)
            body = function_body(text, match.end())
            param_types = parse_param_types(params)
            for receiver, param_name in ASSIGN_PARAM_RE.findall(body):
                if receiver not in state_var_types:
                    continue
                param_type = param_types.get(param_name, "")
                if not param_type or param_type[0].islower():
                    continue
                state_bindings.setdefault(receiver, [])
                if param_type not in state_bindings[receiver]:
                    state_bindings[receiver].append(param_type)
            for receiver, member_owner, callee_name in MEMBER_ASSIGN_RE.findall(body):
                if receiver not in state_var_types:
                    continue
                owner_type = param_types.get(member_owner, state_var_types.get(member_owner, ""))
                if not owner_type or owner_type[0].islower():
                    continue
                for bound_type in helper_return_types.get(callee_name, []):
                    state_bindings.setdefault(receiver, [])
                    if bound_type not in state_bindings[receiver]:
                        state_bindings[receiver].append(bound_type)

        function_hits = []
        for match in function_matches:
            name = match.group(1)
            params = match.group(2)
            suffix = match.group(3)
            body = function_body(text, match.end())
            auth_guards = ROLE_GUARD_RE.findall(suffix)
            if OWNER_GUARD_RE.search(suffix) or OWNER_GUARD_RE.search(body):
                auth_guards.append("OWNER")
            for require_expr in REQUIRE_RE.findall(body):
                if "msg.sender" not in require_expr:
                    continue
                for require_match in MSG_SENDER_REQUIRE_RE.finditer(require_expr):
                    guard_target = require_match.group(1) or require_match.group(2)
                    if guard_target:
                        auth_guards.append(guard_target)
            require_guards = [expr for expr in REQUIRE_RE.findall(body) if "msg.sender" in expr][:8]
            modifiers = [
                token
                for token in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", suffix)
                if token not in {"public", "external", "internal", "private", "view", "pure", "payable", "virtual", "override"}
            ]
            writes = sorted(set(WRITE_HINT_RE.findall(body)))[:16]
            true_writes = [
                token for token in sorted(set(BOOL_TRUE_ASSIGN_RE.findall(body)))
                if token in state_var_names
            ][:16]
            false_writes = [
                token for token in sorted(set(BOOL_FALSE_ASSIGN_RE.findall(body)))
                if token in state_var_names
            ][:16]
            state_reads = [
                token for token in sorted(set(WORD_RE.findall(body)))
                if token in state_var_names and token not in writes
            ][:16]
            internal_calls = [
                token
                for token in sorted(set(INTERNAL_CALL_RE.findall(body)))
                if token not in CALL_KEYWORDS and token != name
            ][:16]
            member_calls = []
            for receiver, called_function in MEMBER_CALL_RE.findall(body):
                if receiver not in state_var_types:
                    continue
                member_calls.append(
                    {
                        "receiver": receiver,
                        "receiver_type": state_var_types[receiver],
                        "bound_types": state_bindings.get(receiver, []),
                        "function": called_function,
                    }
                )
            slot_assignments = []
            for target, source in ASSIGN_PARAM_RE.findall(body):
                if target not in state_var_types or source not in state_var_types:
                    continue
                slot_assignments.append(
                    {
                        "target": target,
                        "source": source,
                    }
                )
            function_hits.append(
                {
                    "contract": owner_contract_name(match.start(), contract_blocks),
                    "name": name,
                    "params": params.strip(),
                    "visibility": (
                        "external" if "external" in suffix else
                        "public" if "public" in suffix else
                        "private" if "private" in suffix else
                        "internal"
                    ),
                    "modifiers": modifiers,
                    "auth_guards": sorted(set(auth_guards)),
                    "writes": writes,
                    "true_writes": true_writes,
                    "false_writes": false_writes,
                    "state_reads": state_reads,
                    "external_calls": sorted(set(EXTERNAL_CALL_RE.findall(body))),
                    "internal_calls": internal_calls,
                    "member_calls": member_calls[:16],
                    "slot_assignments": slot_assignments[:16],
                    "require_guards": sorted(set(require_guards)),
                    "role_constants": [role for role in role_constants if role in body or role in suffix],
                    "sink_hints": [token for token in SINK_HINTS if token in name.lower()],
                    "state_keywords": [token for token in STATE_KEYWORDS if token in name.lower()],
                    "line_start": line_number(text, match.start()),
                    "line_end": line_number(text, match.end() + len(body)),
                }
            )
        file_entries.append({"path": rel, "contracts": contract_hits, "functions": function_hits, "state_vars": state_vars, "state_bindings": state_bindings, "role_constants": role_constants})
        for contract in contract_hits:
            contracts.append({"path": rel, **contract, "role_constants": role_constants})

    payload = {"files": file_entries, "contracts": contracts}
    write_text(Path(artifacts["semantic_index"]), json.dumps(payload, indent=2, sort_keys=True) + "\n")
    status = PhaseStatus(
        phase="semantic_index",
        ok=bool(contracts),
        mode="full",
        artifacts=artifacts,
        warnings=[],
        errors=[],
        details={"target_dir": str(target_dir), "contract_count": len(contracts), "file_count": len(file_entries)},
    )
    return finalize(status)


if __name__ == "__main__":
    raise SystemExit(main())
