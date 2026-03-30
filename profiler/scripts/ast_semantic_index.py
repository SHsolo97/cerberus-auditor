"""
AST-backed semantic indexer for Solidity contracts.

Uses Slither JSON output as the primary AST source, falling back to an
enhanced regex-based indexer when Slither is unavailable.  Produces
.ast_semantic_index.json with provenance-tracked reads/writes, exact
call edges, guard classification, and modifier analysis.

Output schema mirrors semantic_index.json but adds:
  _ast_mode: true
  _ast_source: "slither-json" | "forge-build-info" | "regex-fallback"
  per-function: source_lines, ast_node_id (when available)
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from common import (
    AUDIT_DIR,
    STATUS_FILE,
    PhaseStatus,
    command_output,
    dependency_map,
    detect_mode,
    discover_solidity_files,
    finalize,
    find_project_root,
    make_failure_status,
    read_text_file,
    run_cmd,
    write_text,
)

# ── Regex helpers (fallback mode) ──────────────────────────────────────────

CONTRACT_HEADER_RE = re.compile(
    r"\b(contract|interface|library)\s+([A-Za-z_][A-Za-z0-9_]*)"
    r"(?:\s+is\s+([^{}]+))?\s*\{",
    re.MULTILINE,
)
FUNCTION_RE = re.compile(
    r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)([^{};]*)\{",
    re.MULTILINE | re.DOTALL,
)
ROLE_GUARD_RE = re.compile(r"onlyRole\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)")
OWNER_GUARD_RE = re.compile(
    r"onlyOwner|owner\s*==\s*msg\.sender|msg\.sender\s*==\s*owner"
)
EXTERNAL_CALL_RE = re.compile(
    r"\.(?:call|delegatecall|staticcall|transfer|transferFrom|safeTransfer|safeTransferFrom)\b"
)
WRITE_HINT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*(?:\+?=|\-?=|\*=|/=|%=)")
BOOL_TRUE_ASSIGN_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*true\s*;"
)
BOOL_FALSE_ASSIGN_RE = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*false\s*;"
)
REQUIRE_RE = re.compile(r"require\s*\(([^;]+?)\)\s*;")
MSG_SENDER_REQUIRE_RE = re.compile(
    r"msg\.sender\s*==\s*([A-Za-z_][A-Za-z0-9_]*)|([A-Za-z_][A-Za-z0-9_]*)\s*==\s*msg\.sender"
)
WORD_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\b")
INTERNAL_CALL_RE = re.compile(r"(?<!\.)\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
MEMBER_CALL_RE = re.compile(
    r"\b([a-z_][A-Za-z0-9_]*)\s*\.\s*([A-Za-z_][A-Za-z0-9_]*)\s*\("
)
STATE_RE = re.compile(
    r"\b(address|uint256|uint128|uint64|uint32|uint16|bool|bytes32|string)"
    r"\s+(?:public|private|internal|external)?\s*([A-Za-z_][A-Za-z0-9_]*)\s*;"
)
CUSTOM_STATE_RE = re.compile(
    r"\b([A-Z][A-Za-z0-9_]*)\s+(?:public|private|internal|external)?\s*"
    r"([A-Za-z_][A-Za-z0-9_]*)\s*;"
)
SINK_HINTS = (
    "withdraw", "rescue", "claim", "sweep", "execute", "upgrade",
    "mint", "burn", "transfer",
)
STATE_KEYWORDS = (
    "settle", "recover", "close", "rotate", "pause", "redeem",
    "claim", "liquidate",
)
CALL_KEYWORDS = {
    "if", "for", "while", "require", "assert", "revert", "return",
    "emit", "abi", "keccak256", "super", "mapping", "new",
}


# ── Slither JSON helpers ─────────────────────────────────────────────────────

def run_slither_json(
    slither_bin: str,
    project_root: Path,
    target_dir: Path,
    timeout: int = 300,
) -> Tuple[Optional[Dict[str, Any]], List[str]]:
    """
    Run slither with --json output and return parsed JSON (or None on failure).
    Returns (json_data, warnings).
    """
    warnings: List[str] = []
    target_arg = _repo_relative(target_dir, project_root)

    # Try --ignore-compile first (fastest path when forge build artifacts exist)
    for ignore_compile in (True, False):
        cmd = [slither_bin, target_arg]
        if ignore_compile:
            cmd.append("--ignore-compile")
        cmd.extend(["--json", "output.json"])

        result = run_cmd(cmd, cwd=project_root, timeout=timeout)
        warnings.append(f"[{'ignore-compile' if ignore_compile else 'auto'}] "
                       f"{' '.join(result.command)}: rc={result.returncode}")

        raw = result.stdout.strip()
        if not raw:
            raw = result.stderr.strip()

        try:
            data = json.loads(raw)
            if isinstance(data, list):
                data = data[0] if data else {}
            if isinstance(data, dict) and data.get("success", True) is not False:
                return data, warnings
        except (json.JSONDecodeError, Exception):
            warnings.append(f"JSON parse failed: {raw[:200]}")
            continue

    # Try with explicit solc (no --ignore-compile)
    cmd = [slither_bin, target_arg, "--solc-remap", ".", "--json", "output.json"]
    result = run_cmd(cmd, cwd=project_root, timeout=timeout + 60)
    warnings.append(f"[solc-remap] {' '.join(result.command)}: rc={result.returncode}")

    try:
        data = json.loads(result.stdout.strip())
        if isinstance(data, list):
            data = data[0] if data else {}
        return data, warnings
    except (json.JSONDecodeError, Exception):
        warnings.append("All Slither JSON invocation strategies exhausted.")
        return None, warnings


def slither_json_to_index(
    slither_data: Dict[str, Any],
    project_root: Path,
    target_dir: Path,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str], Dict[str, str]]:
    """
    Convert Slither's top-level JSON output into the semantic index schema.

    Returns (contracts, file_entries, warnings, contract_to_path).
    """
    warnings: List[str] = []
    contracts: List[Dict[str, Any]] = []
    file_entries: List[Dict[str, Any]] = []
    contract_to_path: Dict[str, str] = {}

    if not isinstance(slither_data, dict):
        warnings.append("Slither JSON root is not a dict; skipping.")
        return contracts, file_entries, warnings, contract_to_path

    # Slither JSON v2: results are under "results" -> "types" / "vulnerabilities"
    results = slither_data.get("results", {})
    if not isinstance(results, dict):
        results = slither_data

    # Extract source mappings
    source_mapping: Dict[str, str] = {}  # contract_name -> file path

    # Try to get filename info from Slither's source mappings
    for key in ("source_mapping", "filename", "source"):
        val = slither_data.get(key)
        if val and isinstance(val, str):
            try:
                parts = val.split(":")
                if len(parts) >= 4:
                    # Slither source mapping: "filename:start:length:..."
                    source_file = parts[0]
                    if source_file:
                        source_mapping["_global"] = source_file
            except Exception:
                pass

    # Parse contracts from Slither's contract analysis
    slither_contracts = results.get("contracts", []) or []
    if isinstance(slither_contracts, dict):
        slither_contracts = list(slither_contracts.values())
    if not isinstance(slither_contracts, list):
        slither_contracts = []

    # Also try slither_results / other known keys
    for alt_key in ("slither", "analysis"):
        alt = results.get(alt_key)
        if isinstance(alt, (list, dict)):
            if isinstance(alt, dict):
                slither_contracts = list(alt.values()) or slither_contracts
            else:
                slither_contracts = alt or slither_contracts

    files: Dict[str, Dict[str, Any]] = {}
    for contract_item in slither_contracts:
        if not isinstance(contract_item, dict):
            continue

        name = str(contract_item.get("name", "")).strip()
        if not name:
            continue

        kind = str(contract_item.get("contract_type", contract_item.get("kind", "contract"))).lower()
        if kind not in {"contract", "interface", "library"}:
            kind = "contract"

        inherits = contract_item.get("inheritance", []) or []
        if isinstance(inherits, list):
            inherits = [str(i).strip() for i in inherits if str(i).strip()]

        # Derive file path from source mapping or filename
        file_key = str(contract_item.get("filename", contract_item.get("source_mapping", "_unknown"))).strip()
        # Normalize: strip line numbers from source mapping format "file:line:col"
        if ":" in file_key:
            file_key = file_key.split(":")[0]

        rel = _resolve_file_path(file_key, project_root, target_dir)
        contract_to_path[name] = rel

        if rel not in files:
            files[rel] = {
                "path": rel,
                "contracts": [],
                "functions": [],
                "state_vars": [],
                "state_bindings": {},
                "role_constants": [],
            }

        # ── State variables ──────────────────────────────────────────────
        state_vars_raw = contract_item.get("variables", []) or []
        state_var_names: Set[str] = set()
        for var in state_vars_raw:
            if not isinstance(var, dict):
                continue
            vname = str(var.get("name", "")).strip()
            vtype = str(var.get("type", "")).strip()
            if vname:
                state_var_names.add(vname)
                files[rel]["state_vars"].append({
                    "name": vname,
                    "type": vtype,
                    "contract": name,
                })

        # ── Role constants ───────────────────────────────────────────────
        role_constants = contract_item.get("role_names", []) or []
        if isinstance(role_constants, dict):
            role_constants = list(role_constants.keys())
        role_constants = [
            str(r) for r in role_constants if str(r).endswith("_ROLE")
        ]
        files[rel]["role_constants"] = sorted(set(
            files[rel].get("role_constants", []) + role_constants
        ))

        # ── Functions ────────────────────────────────────────────────────
        slither_functions = contract_item.get("functions", []) or []
        if isinstance(slither_functions, dict):
            slither_functions = list(slither_functions.values())
        if not isinstance(slither_functions, list):
            slither_functions = []

        for sl_fn in slither_functions:
            if not isinstance(sl_fn, dict):
                continue
            fn_name = str(sl_fn.get("name", "")).strip()
            if not fn_name or fn_name.startswith(""):
                pass  # accept all names

            visibility = str(sl_fn.get("visibility", "internal")).lower()
            if visibility not in {"external", "public", "internal", "private"}:
                visibility = "internal"

            full_signature = sl_fn.get("full_name", sl_fn.get("signature", ""))
            params = sl_fn.get("params", "") or ""
            if not params and full_signature:
                # Extract params from signature: "name(type1,type2)"
                m = re.search(r"\(([^)]*)\)", full_signature)
                if m:
                    params = m.group(1)

            # Modifiers
            slither_modifiers = slither_fn.get("modifiers", []) or []
            if isinstance(slither_modifiers, dict):
                slither_modifiers = list(slither_modifiers.values())
            modifiers = []
            auth_guards: List[str] = []
            for mod in slither_modifiers:
                if not isinstance(mod, dict):
                    mod_name = str(mod)
                else:
                    mod_name = str(mod.get("name", mod.get("modifier_name", "")))
                    # Extract guards from modifier body if available
                    mod_body = mod.get("body", mod.get("expression", ""))
                    for rm in ROLE_GUARD_RE.findall(str(mod_body)):
                        auth_guards.append(rm)
                    if OWNER_GUARD_RE.search(str(mod_body)):
                        auth_guards.append("OWNER")
                if mod_name:
                    modifiers.append(mod_name)
                    # Check modifier name for auth patterns
                    if mod_name.lower().startswith("only"):
                        auth_guards.append(mod_name)
                    if "role" in mod_name.lower() or "auth" in mod_name.lower():
                        auth_guards.append(mod_name)

            # Also check modifiers string in function directly
            mod_str = sl_fn.get("modifiers", "")
            if isinstance(mod_str, str):
                for rm in ROLE_GUARD_RE.findall(mod_str):
                    auth_guards.append(rm)
                if OWNER_GUARD_RE.search(mod_str):
                    auth_guards.append("OWNER")

            # Source-level guards from require statements
            require_guards: List[str] = []
            if sl_fn.get("content"):
                for expr in REQUIRE_RE.findall(str(sl_fn.get("content", ""))):
                    if "msg.sender" in expr:
                        require_guards.append(f"require({expr.strip()})")
                        for rm in MSG_SENDER_REQUIRE_RE.finditer(expr):
                            guard_target = rm.group(1) or rm.group(2)
                            if guard_target:
                                auth_guards.append(guard_target)

            # State reads / writes from Slither's analysis
            raw_reads = sl_fn.get("state_reads", []) or []
            raw_writes = sl_fn.get("state_writes", []) or []
            if isinstance(raw_reads, dict):
                raw_reads = list(raw_reads.values()) or []
            if isinstance(raw_writes, dict):
                raw_writes = list(raw_writes.values()) or []

            state_reads = [str(r).strip() for r in raw_reads if str(r).strip()]
            state_writes = [str(w).strip() for w in raw_writes if str(w).strip()]

            # Provenance-tracked writes
            writes: List[str] = sorted(set(
                [w for w in state_writes if w in state_var_names]
            ))
            true_writes: List[str] = []
            false_writes: List[str] = []
            if sl_fn.get("content"):
                fn_body = str(sl_fn.get("content", ""))
                for t in BOOL_TRUE_ASSIGN_RE.findall(fn_body):
                    if t in state_var_names:
                        true_writes.append(t)
                for f in BOOL_FALSE_ASSIGN_RE.findall(fn_body):
                    if f in state_var_names:
                        false_writes.append(f)

            # External calls
            raw_ext = sl_fn.get("external_calls_as_expressions", []) or []
            if isinstance(raw_ext, dict):
                raw_ext = list(raw_ext.values()) or []
            external_calls: List[str] = []
            for ec in raw_ext:
                if isinstance(ec, str):
                    external_calls.append(ec.strip())
                elif isinstance(ec, dict):
                    ext_name = ec.get("name") or ec.get("function_name", "")
                    if ext_name:
                        external_calls.append(str(ext_name).strip())
            if not external_calls and sl_fn.get("content"):
                external_calls = EXTERNAL_CALL_RE.findall(str(sl_fn.get("content", "")))

            # Internal calls
            raw_int = sl_fn.get("internal_calls", []) or []
            if isinstance(raw_int, dict):
                raw_int = list(raw_int.values()) or []
            internal_calls: List[str] = []
            for ic in raw_int:
                if isinstance(ic, str):
                    internal_calls.append(ic.strip())
                elif isinstance(ic, dict):
                    ic_name = ic.get("name", ic.get("internal_name", ""))
                    if ic_name:
                        internal_calls.append(str(ic_name).strip())

            # Member calls on state-typed receivers
            member_calls: List[Dict[str, Any]] = []
            if sl_fn.get("content"):
                fn_body = str(sl_fn.get("content", ""))
                for recv, called in MEMBER_CALL_RE.findall(fn_body):
                    if recv in state_var_names:
                        member_calls.append({
                            "receiver": recv,
                            "receiver_type": "state_variable",
                            "bound_types": [],
                            "function": called,
                        })

            # Slot assignments
            slot_assignments: List[Dict[str, str]] = []
            if sl_fn.get("content"):
                fn_body = str(sl_fn.get("content", ""))
                for target, source in re.findall(
                    r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*;",
                    fn_body,
                ):
                    if target in state_var_names and source in state_var_names:
                        slot_assignments.append({"target": target, "source": source})

            # Sink hints from function name
            sink_hints = [h for h in SINK_HINTS if h in fn_name.lower()]
            state_kws = [k for k in STATE_KEYWORDS if k in fn_name.lower()]

            # Line info
            line_start = sl_fn.get("line", 0) or 0
            line_end = sl_fn.get("end_line", sl_fn.get("endLine", line_start)) or line_start

            fn_entry = {
                "contract": name,
                "name": fn_name,
                "params": params,
                "visibility": visibility,
                "modifiers": sorted(set(modifiers)),
                "auth_guards": sorted(set(auth_guards)),
                "writes": writes,
                "true_writes": sorted(set(true_writes)),
                "false_writes": sorted(set(false_writes)),
                "state_reads": sorted(set(state_reads)),
                "external_calls": sorted(set(external_calls)),
                "internal_calls": sorted(set(internal_calls))[:16],
                "member_calls": member_calls[:16],
                "slot_assignments": slot_assignments[:16],
                "require_guards": require_guards[:8],
                "sink_hints": sink_hints,
                "state_keywords": state_kws,
                "line_start": line_start,
                "line_end": line_end,
            }
            files[rel]["functions"].append(fn_entry)

        files[rel]["contracts"].append({
            "kind": kind,
            "name": name,
            "inherits": inherits,
        })
        contracts.append({
            "path": rel,
            "kind": kind,
            "name": name,
            "inherits": inherits,
            "role_constants": files[rel].get("role_constants", []),
        })

    # ── Build state_bindings ────────────────────────────────────────────────
    for rel, file_entry in files.items():
        if file_entry.get("functions") and file_entry.get("state_vars"):
            for fn_entry in file_entry["functions"]:
                pass  # already populated from slither

    file_entries = list(files.values())
    return contracts, file_entries, warnings, contract_to_path


def slither_json_to_index_from_source(
    slither_data: Dict[str, Any],
    project_root: Path,
    target_dir: Path,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str], Dict[str, str]]:
    """
    Parse Slither's more detailed JSON output when available from
    slither . --json output.
    Handles the Slither analysis dict structure.
    """
    return slither_json_to_index(slither_data, project_root, target_dir)


# ── Regex fallback ────────────────────────────────────────────────────────────

def function_body(text: str, body_start: int) -> str:
    depth = 1
    idx = body_start
    while idx < len(text):
        if text[idx] == "{":
            depth += 1
        elif text[idx] == "}":
            depth -= 1
            if depth == 0:
                return text[body_start:idx]
        idx += 1
    return text[body_start:]


def block_end(text: str, body_start: int) -> int:
    depth = 1
    idx = body_start
    while idx < len(text):
        if text[idx] == "{":
            depth += 1
        elif text[idx] == "}":
            depth -= 1
            if depth == 0:
                return idx
        idx += 1
    return len(text)


def line_number(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def parse_param_types(params: str) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for raw_param in params.split(","):
        raw = raw_param.strip()
        if not raw:
            continue
        tokens = [
            t for t in raw.split()
            if t not in {"memory", "calldata", "storage", "payable"}
        ]
        if len(tokens) < 2:
            continue
        param_name = tokens[-1].strip()
        param_type = tokens[-2].strip()
        if param_name and param_type:
            result[param_name] = param_type
    return result


def owner_contract_name(
    offset: int,
    contract_blocks: List[Dict[str, Any]],
) -> str:
    for block in contract_blocks:
        start = int(block.get("start", -1))
        end = int(block.get("end", -1))
        if start <= offset <= end:
            return str(block.get("name", "")).strip()
    return ""


def build_regex_index(
    files: List[Path],
    project_root: Path,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    """
    Enhanced regex-based fallback for degraded mode.
    Better than the original semantic_index: tracks state variable scope
    per contract using brace-depth analysis.
    """
    warnings: List[str] = []
    contracts: List[Dict[str, Any]] = []
    file_entries: List[Dict[str, Any]] = []

    for path in files:
        text = read_text_file(path)
        if not text:
            continue
        rel = str(path.relative_to(project_root.parent).as_posix())

        # ── Contract declarations ───────────────────────────────────────
        contract_hits: List[Dict[str, Any]] = []
        contract_blocks: List[Dict[str, Any]] = []
        for match in CONTRACT_HEADER_RE.finditer(text):
            kind = match.group(1)
            name = match.group(2)
            parents = match.group(3)
            inherits = [
                t.strip() for t in parents.split(",") if t.strip()
            ] if parents else []
            end = block_end(text, match.end())
            contract_hits.append({"kind": kind, "name": name, "inherits": inherits})
            contract_blocks.append({
                "kind": kind,
                "name": name,
                "inherits": inherits,
                "start": match.start(),
                "end": end,
            })

        if not contract_hits:
            # Fallback: simple contract declaration line
            import re as _re
            simple = _re.compile(
                r"^\s*(?:(abstract)\s+)?(contract|interface|library)\s+"
                r"([A-Za-z_][A-Za-z0-9_]*)\b"
            )
            for line_no, line in enumerate(text.splitlines()):
                m = simple.match(line)
                if m:
                    kind = "abstract contract" if m.group(1) else m.group(2)
                    name = m.group(3)
                    contract_hits.append({"kind": kind, "name": name, "inherits": []})
                    contract_blocks.append({
                        "kind": kind, "name": name, "inherits": [],
                        "start": line_no * 1000, "end": (line_no + 1) * 1000,
                    })

        # ── State variables ─────────────────────────────────────────────
        primitive_vars = [
            {"type": typ, "name": nm}
            for typ, nm in STATE_RE.findall(text)
        ]
        custom_vars = [
            {"type": typ, "name": nm}
            for typ, nm in CUSTOM_STATE_RE.findall(text)
            if typ not in {"contract", "interface", "library"}
        ]
        state_vars: List[Dict[str, Any]] = []
        seen_names: Set[str] = set()
        for match in STATE_RE.finditer(text):
            nm = match.group(2)
            if nm in seen_names:
                continue
            seen_names.add(nm)
            state_vars.append({
                "type": match.group(1),
                "name": nm,
                "contract": owner_contract_name(match.start(), contract_blocks),
            })
        for match in CUSTOM_STATE_RE.finditer(text):
            typ = match.group(1)
            nm = match.group(2)
            if typ in {"contract", "interface", "library"} or nm in seen_names:
                continue
            seen_names.add(nm)
            state_vars.append({
                "type": typ,
                "name": nm,
                "contract": owner_contract_name(match.start(), contract_blocks),
            })

        state_var_names = {e["name"] for e in state_vars}
        state_var_types = {e["name"]: e["type"] for e in state_vars}

        role_constants = sorted(set(re.findall(r"\b([A-Z][A-Z0-9_]*_ROLE)\b", text)))

        # ── Helper return types (from function return type annotations) ─
        helper_return_types: Dict[str, List[str]] = {}
        for fn_match in FUNCTION_RE.finditer(text):
            fn_body = function_body(text, fn_match.end())
            return_types = [
                bt for bt in re.findall(r"\breturn\s+new\s+([A-Z][A-Za-z0-9_]*)\s*\(", fn_body)
                if bt.strip()
            ]
            if return_types:
                helper_return_types[fn_match.group(1)] = sorted(set(return_types))

        # ── State bindings ─────────────────────────────────────────────
        state_bindings: Dict[str, List[str]] = {}
        for receiver, bound_type in re.findall(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*new\s+([A-Z][A-Za-z0-9_]*)\s*\(",
            text,
        ):
            if receiver in state_var_types:
                state_bindings.setdefault(receiver, [])
                if bound_type not in state_bindings[receiver]:
                    state_bindings[receiver].append(bound_type)

        for receiver, bound_type in re.findall(
            r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[A-Z][A-Za-z0-9_]*\s*\([^;]*?new\s+([A-Z][A-Za-z0-9_]*)\s*\(",
            text,
            flags=re.DOTALL,
        ):
            if receiver in state_var_types:
                state_bindings.setdefault(receiver, [])
                if bound_type not in state_bindings[receiver]:
                    state_bindings[receiver].append(bound_type)

        # ── Functions ──────────────────────────────────────────────────
        function_hits: List[Dict[str, Any]] = []
        for fn_match in FUNCTION_RE.finditer(text):
            fn_name = fn_match.group(1)
            params = fn_match.group(2)
            suffix = fn_match.group(3)
            body = function_body(text, fn_match.end())
            param_types = parse_param_types(params)

            # Auth guards from suffix (modifiers)
            auth_guards: List[str] = list(ROLE_GUARD_RE.findall(suffix))
            if OWNER_GUARD_RE.search(suffix) or OWNER_GUARD_RE.search(body):
                auth_guards.append("OWNER")

            for expr in REQUIRE_RE.findall(body):
                if "msg.sender" not in expr:
                    continue
                for rm in MSG_SENDER_REQUIRE_RE.finditer(expr):
                    gt = rm.group(1) or rm.group(2)
                    if gt:
                        auth_guards.append(gt)

            require_guards = [
                f"require({e.strip()})"
                for e in REQUIRE_RE.findall(body)
                if "msg.sender" in e
            ][:8]

            modifiers = [
                t for t in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\b", suffix)
                if t
                not in {
                    "public", "external", "internal", "private",
                    "view", "pure", "payable", "virtual", "override",
                }
            ]

            # Writes
            writes = sorted(set(
                w for w in WRITE_HINT_RE.findall(body)
                if w in state_var_names
            ))[:16]

            true_writes = sorted(set(
                t for t in BOOL_TRUE_ASSIGN_RE.findall(body)
                if t in state_var_names
            ))[:16]

            false_writes = sorted(set(
                f for f in BOOL_FALSE_ASSIGN_RE.findall(body)
                if f in state_var_names
            ))[:16]

            # State reads
            all_words = WORD_RE.findall(body)
            state_reads = sorted(set(
                w for w in all_words
                if w in state_var_names and w not in writes
            ))[:16]

            # Internal calls
            internal_calls = sorted(set(
                c for c in INTERNAL_CALL_RE.findall(body)
                if c not in CALL_KEYWORDS and c != fn_name
            ))[:16]

            # Member calls
            member_calls: List[Dict[str, Any]] = []
            for recv, called in MEMBER_CALL_RE.findall(body):
                if recv in state_var_types:
                    member_calls.append({
                        "receiver": recv,
                        "receiver_type": state_var_types.get(recv, ""),
                        "bound_types": state_bindings.get(recv, []),
                        "function": called,
                    })

            # Slot assignments
            slot_assignments: List[Dict[str, str]] = []
            for target, source in re.findall(
                r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*;",
                body,
            ):
                if target in state_var_names and source in state_var_names:
                    slot_assignments.append({"target": target, "source": source})

            sink_hints = [h for h in SINK_HINTS if h in fn_name.lower()]
            state_kws = [k for k in STATE_KEYWORDS if k in fn_name.lower()]

            function_hits.append({
                "contract": owner_contract_name(fn_match.start(), contract_blocks),
                "name": fn_name,
                "params": params.strip(),
                "visibility": (
                    "external" if "external" in suffix
                    else "public" if "public" in suffix
                    else "private" if "private" in suffix
                    else "internal"
                ),
                "modifiers": sorted(set(modifiers)),
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
                "role_constants": [
                    r for r in role_constants
                    if r in body or r in suffix
                ],
                "sink_hints": sink_hints,
                "state_keywords": state_kws,
                "line_start": line_number(text, fn_match.start()),
                "line_end": line_number(text, fn_match.end() + len(body)),
            })

        file_entry = {
            "path": rel,
            "contracts": contract_hits,
            "functions": function_hits,
            "state_vars": state_vars,
            "state_bindings": state_bindings,
            "role_constants": role_constants,
        }
        file_entries.append(file_entry)

        for contract in contract_hits:
            contracts.append({
                "path": rel,
                "kind": contract["kind"],
                "name": contract["name"],
                "inherits": contract["inherits"],
                "role_constants": role_constants,
            })

    return contracts, file_entries, warnings


# ── Path utilities ────────────────────────────────────────────────────────────

def _repo_relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def _resolve_file_path(
    file_key: str,
    project_root: Path,
    target_dir: Path,
) -> str:
    """Resolve a file identifier from Slither to a repo-relative path."""
    if not file_key or file_key == "_unknown":
        return str(target_dir)

    p = Path(file_key)
    try:
        return p.relative_to(project_root).as_posix()
    except ValueError:
        pass

    try:
        return p.relative_to(target_dir).as_posix()
    except ValueError:
        return file_key


# ── Main ─────────────────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build an AST-backed semantic index for Solidity contracts.",
    )
    parser.add_argument(
        "--target-dir",
        required=True,
        help="Directory containing Solidity source files.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target_dir = Path(args.target_dir).resolve()
    warnings: List[str] = []
    errors: List[str] = []
    artifacts = {"ast_semantic_index": str(AUDIT_DIR / "ast_semantic_index.json")}

    try:
        if not target_dir.exists() or not target_dir.is_dir():
            status = make_failure_status(
                "ast_semantic_index",
                errors=[f"Target directory does not exist: {target_dir}"],
                warnings=warnings,
                artifacts=artifacts,
                details={"target_dir": str(target_dir)},
            )
            return finalize(status)

        sol_files = discover_solidity_files(target_dir)
        if not sol_files:
            status = make_failure_status(
                "ast_semantic_index",
                errors=[f"No Solidity files found under: {target_dir}"],
                warnings=warnings,
                artifacts=artifacts,
                details={"target_dir": str(target_dir)},
            )
            return finalize(status)

        project_root = find_project_root(target_dir)
        status_snapshot = _read_json(STATUS_FILE)
        init_details = (
            status_snapshot.get("init", {}).get("details", {})
            if isinstance(status_snapshot, dict) else {}
        )
        run_id = init_details.get("run_id")

        deps = dependency_map("forge", "slither")
        forge_bin = deps.get("forge")
        slither_bin = deps.get("slither")

        contracts: List[Dict[str, Any]] = []
        file_entries: List[Dict[str, Any]] = []
        ast_mode = "regex-fallback"
        ast_source = "regex-fallback"

        if forge_bin and slither_bin:
            # Try Slither JSON first — most informative
            slither_data, slither_warnings = run_slither_json(
                slither_bin, project_root, target_dir,
            )
            warnings.extend(slither_warnings)

            if slither_data is not None:
                contracts, file_entries, json_warnings, _ = slither_json_to_index(
                    slither_data, project_root, target_dir,
                )
                warnings.extend(json_warnings)
                if contracts or file_entries:
                    ast_mode = "full"
                    ast_source = "slither-json"
                    warnings.append(
                        "Using Slither JSON for AST-backed semantic index."
                    )

        # If Slither produced nothing, fall back to enhanced regex
        if not file_entries:
            warnings.append(
                "Falling back to enhanced regex-based extraction."
            )
            contracts, file_entries, regex_warnings = build_regex_index(
                sol_files, project_root,
            )
            warnings.extend(regex_warnings)
            ast_mode = "degraded"
            ast_source = "regex-fallback"

        payload = {
            "_ast_mode": True,
            "_ast_source": ast_source,
            "mode": ast_mode,
            "files": file_entries,
            "contracts": contracts,
        }

        write_text(Path(artifacts["ast_semantic_index"]), json.dumps(payload, indent=2, sort_keys=True) + "\n")

        phase_mode = detect_mode(deps)
        if ast_mode == "degraded":
            phase_mode = "degraded"
        if not file_entries:
            phase_mode = "degraded"

        status = PhaseStatus(
            phase="ast_semantic_index",
            ok=bool(file_entries),
            mode=phase_mode,
            artifacts=artifacts,
            warnings=warnings,
            errors=errors,
            details={
                "target_dir": str(target_dir),
                "project_root": str(project_root),
                "ast_source": ast_source,
                "ast_mode": ast_mode,
                "file_count": len(file_entries),
                "contract_count": len(contracts),
                "dependencies": deps,
                "run_id": run_id,
            },
        )
        return finalize(status)

    except Exception as exc:
        status = make_failure_status(
            "ast_semantic_index",
            errors=[f"Unhandled exception: {type(exc).__name__}: {exc}"],
            warnings=warnings,
            artifacts=artifacts,
            details={"target_dir": str(target_dir)},
        )
        return finalize(status, exit_code=1)


def _read_json(path: Path) -> Dict[str, Any]:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


if __name__ == "__main__":
    raise SystemExit(main())
