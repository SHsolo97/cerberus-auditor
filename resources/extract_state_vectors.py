from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from common import (
    AUDIT_DIR,
    STATUS_FILE,
    PhaseStatus,
    ToolchainConfig,
    choose_slither_printer,
    command_output,
    dependency_map,
    detect_mode,
    discover_solidity_files,
    fatal_status,
    finalize,
    find_project_root,
    get_slither_printers,
    make_failure_status,
    prepare_slither_build,
    read_json,
    read_text_file as read_text,
    repo_relative_path,
    resolve_toolchain,
    run_cmd,
    slither_command_candidates,
    usable_slither_output,
    write_text,
)


CONTRACT_DECLARATION_RE = re.compile(
    r"^\s*(?:(abstract)\s+)?(contract|library|interface)\s+([A-Za-z_][A-Za-z0-9_]*)\b"
)
COMMENT_LINE_PREFIXES = ("//", "///", "*")
FUNCTION_BODY_RE = re.compile(
    r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(([^)]*)\)([^{};]*?)\{",
    re.MULTILINE | re.DOTALL,
)
ASSIGNMENT_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*=")
ROLE_SETTER_HINT_RE = re.compile(r"\b(grantRole|revokeRole|_grantRole|_revokeRole)\b")


def should_skip_storage_layout_file(sol_file: Path) -> bool:
    lowered = str(sol_file).lower()
    skip_dirs = ("/test/", "/interfaces/", "/interface/", "/mock/", "/mocks/", "/script/", "/scripts/", "/lib/", "/libs/")
    return any(d in lowered for d in skip_dirs) or lowered.endswith(".t.sol")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Extract state vectors and external boundaries.")
    parser.add_argument("--target-dir", required=True, help="Directory containing Solidity contracts.")
    return parser.parse_args()


def discover_contract_declarations(sol_file: Path) -> List[Tuple[str, str]]:
    declarations: List[Tuple[str, str]] = []
    try:
        content = sol_file.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return declarations

    for line in content.splitlines():
        match = CONTRACT_DECLARATION_RE.match(line)
        if match:
            kind = "abstract contract" if match.group(1) else match.group(2)
            declarations.append((kind, match.group(3)))
    return declarations


def strip_comments_from_line(line: str, *, in_block_comment: bool) -> Tuple[str, bool]:
    idx = 0
    out: List[str] = []
    line_length = len(line)

    while idx < line_length:
        if in_block_comment:
            end_idx = line.find("*/", idx)
            if end_idx == -1:
                return ("".join(out), True)
            idx = end_idx + 2
            in_block_comment = False
            continue

        if line.startswith("//", idx):
            break
        if line.startswith("/*", idx):
            in_block_comment = True
            idx += 2
            continue

        out.append(line[idx])
        idx += 1

    return ("".join(out), in_block_comment)


def collect_delegatecall_hits(files: List[Path]) -> tuple[List[str], List[str]]:
    hits: List[str] = []
    warnings: List[str] = []
    for path in files:
        try:
            in_block_comment = False
            for idx, raw_line in enumerate(path.read_text(encoding="utf-8", errors="ignore").splitlines(), start=1):
                stripped = raw_line.lstrip()
                if not in_block_comment and stripped.startswith(COMMENT_LINE_PREFIXES):
                    continue
                code_only, in_block_comment = strip_comments_from_line(raw_line, in_block_comment=in_block_comment)
                if "delegatecall" in code_only:
                    hits.append(f"{path}:{idx}: {code_only.strip()}")
        except OSError as exc:
            warnings.append(f"Could not read {path}: {exc}")
    return hits, warnings


def inspect_storage_layout(
    contract_identifier: str, *, forge_bin: str, project_root: Path
) -> tuple[Optional[Dict[str, object]], Optional[str], List[str]]:
    warnings: List[str] = []
    result = run_cmd([forge_bin, "inspect", contract_identifier, "storageLayout"], cwd=project_root, timeout=120)
    if not result.ok or not result.stdout.strip():
        stderr = result.stderr.strip().lower()
        if "storage layout missing from artifact" in stderr:
            forced = run_cmd(
                [forge_bin, "inspect", contract_identifier, "storageLayout", "--force"],
                cwd=project_root,
                timeout=240,
            )
            if forced.ok and forced.stdout.strip():
                return (
                    {
                        "format": "text",
                        "raw": forced.stdout,
                        "command": forced.command,
                        "forced": True,
                    },
                    None,
                    warnings,
                )
            warnings.append(f"Storage layout unavailable for {contract_identifier}.")
            return None, None, warnings
        warnings.append(f"Storage layout unavailable for {contract_identifier}.")
        return None, None, warnings

    return (
        {
            "format": "text",
            "raw": result.stdout,
            "command": result.command,
            "forced": False,
        },
        None,
        warnings,
    )


def inspect_storage_layouts(
    files: List[Path], *, forge_bin: str, project_root: Path
) -> tuple[Dict[str, Dict[str, object]], List[str], Set[str]]:
    layouts: Dict[str, Dict[str, object]] = {}
    warnings: List[str] = []
    seen_names: Set[str] = set()

    for sol_file in files:
        if should_skip_storage_layout_file(sol_file):
            continue
        for kind, contract_name in discover_contract_declarations(sol_file):
            if kind != "contract":
                continue
            relative_path = sol_file.relative_to(project_root).as_posix()
            contract_identifier = f"{relative_path}:{contract_name}"
            if contract_identifier in seen_names:
                continue
            seen_names.add(contract_identifier)
            layout, _error, layout_warnings = inspect_storage_layout(
                contract_identifier, forge_bin=forge_bin, project_root=project_root
            )
            warnings.extend(layout_warnings)
            if layout is not None:
                layouts[contract_identifier] = layout
    return layouts, warnings, seen_names


def infer_storage_layout_from_semantic_index(
    files: List[Path], project_root: Path
) -> tuple[Dict[str, Dict[str, object]], List[str], Set[str]]:
    """
    Best-effort storage layout inference from Solidity source files.

    Used when forge inspect is unavailable (non-Foundry projects).
    Produces the same dict structure as forge inspect output, with
    _source: "regex-inference" so downstream consumers know the provenance.

    Limitations:
    - Only handles named variables with explicit types
    - Cannot determine actual storage slots (would need solc or AST)
    - Complex types (mappings, arrays) get a placeholder entry
    """
    layouts: Dict[str, Dict[str, object]] = {}
    warnings: List[str] = []
    seen_names: Set[str] = set()

    # Regex patterns for state variable declarations
    STATE_VAR_RE = re.compile(
        r"^\s*(uint\d*|int\d*|address|bool|bytes\d*|string)\s+"
        r"([A-Za-z_][A-Za-z0-9_]*)\s*(?:\[.*?\])?\s*(?:=|;)",
        re.MULTILINE,
    )
    MAPPING_RE = re.compile(
        r"^\s*mapping\s*\([^)]+\)\s+([A-Za-z_][A-Za-z0-9_]*)\s*(?:=|;)",
        re.MULTILINE,
    )

    for sol_file in files:
        if should_skip_storage_layout_file(sol_file):
            continue
        for kind, contract_name in discover_contract_declarations(sol_file):
            if kind != "contract":
                continue
            relative_path = sol_file.relative_to(project_root).as_posix()
            contract_identifier = f"{relative_path}:{contract_name}"
            if contract_identifier in seen_names:
                continue
            seen_names.add(contract_identifier)

            content = read_text(sol_file)
            if not content:
                continue

            # Find the contract body
            contract_match = re.search(
                rf"contract\s+{re.escape(contract_name)}\s*{{",
                content,
            )
            if not contract_match:
                continue
            body_start = contract_match.end()
            # Find the next contract/library/interface or end of file
            next_contract = re.search(
                r"\n\s*(contract|library|interface|abstract\s+contract)\s+",
                content[body_start:],
            )
            body_end = body_start + next_contract.start() if next_contract else len(content)
            contract_body = content[body_start:body_end]

            vars_found: List[Dict[str, str]] = []
            for match in STATE_VAR_RE.finditer(contract_body):
                type_str = match.group(1)
                name = match.group(2)
                vars_found.append({"type": type_str, "name": name, "slot": "unknown"})

            for match in MAPPING_RE.finditer(contract_body):
                name = match.group(1)
                vars_found.append({"type": "mapping", "name": name, "slot": "unknown"})

            if vars_found:
                layouts[contract_identifier] = {
                    "_source": "regex-inference",
                    "format": "inferred",
                    "raw": json.dumps({"storage": vars_found}, indent=2),
                    "variables": vars_found,
                    "note": "Storage layout inferred from source; slot positions are unknown without solc. "
                    "Use forge inspect or solc --storage-layout for precise slot mapping.",
                }
            else:
                warnings.append(f"No state variables extracted for {contract_identifier}.")

    return layouts, warnings, seen_names


# ── Invariant Candidate Extraction ───────────────────────────────────────────

_INVARIANT_CATEGORIES = [
    (
        "Supply / Mint / Burn Invariants",
        ["totalMinted", "totalSupply", "mintRequests", "redeemRequests",
         "maxSupplyCap", "minMTokenAmount", "mint", "burn", "mintTokens"],
    ),
    (
        "Balance / Asset Flow Invariants",
        ["balanceOf", "_balance", "tokensReceiver", "feeReceiver",
         "paymentToken", "paymentReceiver", "collateralBalance"],
    ),
    (
        "Request State-Machine Invariants",
        ["InstantTransferTokens", "escrow", "isApproved", "isFulfilled",
         "redeemRequest", "approveRequest", "fulfillRequest", "cancelRequest",
         "depositRequest", "withdrawRequest", "requestRedeemer", "isSafe"],
    ),
    (
        "Access Control / Emergency Stop Invariants",
        ["greenlist", "blacklist", "paused", "fnPaused", "pauseFn",
         "unpauseFn", "whenFnNotPaused", "pause", "unpause"],
    ),
    (
        "Cross-Chain / OFT Invariants",
        ["oftCmd", "sendParam", "dstEid", "thisChaindEid", "circulatingSupply",
         "sendOft", "_sendOft", "receiveToSameNetwork", "lzReceive",
         "compose", "lzCompose", "mTokenOft", "paymentTokenOft"],
    ),
    (
        "Oracle / Price Invariants",
        ["latestAnswer", "latestRoundData", "latestTimestamp", "getDataInBase18",
         "feedAdmin", "aggregator", "priceFeed", "stalePrice", "healthyDiff"],
    ),
    (
        "Fee / Rate Invariants",
        ["getFeeAmount", "getBps", "rate", "feeRate", "feeReceiver",
         "collectAccumulatedFees"],
    ),
]


def _strip_comments(content: str) -> str:
    """Remove single-line and multi-line comments from Solidity source."""
    result = []
    in_block = False
    for line in content.splitlines():
        stripped = line
        if in_block:
            if "*/" in stripped:
                stripped = stripped[stripped.index("*/") + 2:]
                in_block = False
            else:
                stripped = ""
        if "/*" in stripped:
            before, after = stripped.split("/*", 1)
            if "*/" in after:
                stripped = before + after[after.index("*/") + 2:]
            else:
                stripped = before
                in_block = True
        # strip // comments
        if "//" in stripped:
            stripped = stripped[:stripped.index("//")]
        result.append(stripped)
    return "\n".join(result)


def collect_invariant_candidates(files: List[Path], project_root: Path) -> str:
    """
    Scan Solidity files for state-mutating patterns that imply protocol invariants.
    Returns a markdown-formatted string written to invariant_map.md.
    """
    lines = [
        "# Invariant Candidates",
        "",
        "*Auto-generated by extract_state_vectors.py. "
        "These are hypothesized invariants derived from source patterns; "
        "they are NOT confirmed until validated against actual protocol behavior.*",
        "",
    ]

    import_source = """
## Import Note

These candidates were derived by scanning source for state-changing patterns.
The confirmed, protocol-level invariants are documented in **01_threat_model.md**.
This map serves as a supplementary reference for phase-2 state-vector coverage.
"""
    lines.append(import_source.strip())
    lines.append("")

    # Build a combined pattern matcher per category
    category_hits: Dict[str, Dict[str, List[str]]] = {}  # category -> contract -> [matches]

    for sol_file in sorted(files):
        rel = repo_relative_path(sol_file, project_root)
        try:
            raw = sol_file.read_text(errors="replace")
        except Exception:
            continue
        stripped = _strip_comments(raw)

        # Find contract declarations in this file
        contracts_in_file: List[str] = []
        for m in CONTRACT_DECLARATION_RE.finditer(stripped):
            cname = m.group(3)
            contracts_in_file.append(cname)

        for category, keywords in _INVARIANT_CATEGORIES:
            if category not in category_hits:
                category_hits[category] = {}
            hits: List[str] = []
            for kw in keywords:
                # count occurrences (case-insensitive)
                count = len(re.findall(rf"\b{re.escape(kw)}\b", stripped, re.IGNORECASE))
                if count > 0:
                    hits.append(f"{kw} ({count} occurrence{'s' if count > 1 else ''})")
            if hits:
                for cname in contracts_in_file:
                    if cname not in category_hits[category]:
                        category_hits[category][cname] = []
                    category_hits[category][cname].extend(hits)

    for category, keywords in _INVARIANT_CATEGORIES:
        lines.append(f"## {category}")
        contracts_with_hits = category_hits.get(category, {})
        if not contracts_with_hits:
            lines.append("No direct pattern hits in scanned contracts.")
        else:
            for contract, hits in sorted(contracts_with_hits.items()):
                unique_hits = sorted(set(hits))
                lines.append(f"### {contract}")
                for h in unique_hits:
                    lines.append(f"- {h}")
        lines.append("")

    lines.append("## Pattern Interpretation Guide")
    guide = """
| Pattern | Implied Invariant |
|---|---|
| `mint` + `maxSupplyCap` | totalMinted ≤ maxSupplyCap |
| `burn` + `redeemRequests` | vault-backed supply ≥ pending redeem obligations |
| `balanceOf` + `tokensReceiver` | vault token balance ≥ cumulative `tokensReceiver` outflow |
| `greenlist` + `blacklist` | blacklisted users cannot deposit or redeem |
| `paused` / `fnPaused` | when paused, no state-mutating functions execute |
| `circulatingSupply` + `dstEid` | OFT supply accounting matches vault supply per chain |
| `latestAnswer` + `healthyDiff` | oracle price must be fresh and within configured bounds |
| `feeReceiver` + `collectAccumulatedFees` | accumulated fees ≤ vault payment token balance |
"""
    lines.append(guide.strip())

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    args = parse_args()
    target_dir = Path(args.target_dir).resolve()
    warnings: List[str] = []
    errors: List[str] = []
    artifacts = {
        "external_calls": str(AUDIT_DIR / "external_calls.txt"),
        "storage_layout": str(AUDIT_DIR / "storage_layout.json"),
        "invariant_map": str(AUDIT_DIR / "invariant_map.md"),
        "tool_log": str(AUDIT_DIR / "phase2_tooling.log"),
    }

    try:
        if not target_dir.exists() or not target_dir.is_dir():
            status = make_failure_status(
                "state_vectors",
                errors=[f"Target directory does not exist or is not a directory: {target_dir}"],
                warnings=warnings,
                artifacts=artifacts,
                details={"target_dir": str(target_dir)},
            )
            return finalize(status)

        files = discover_solidity_files(target_dir)
        if not files:
            status = make_failure_status(
                "state_vectors",
                errors=[f"No Solidity files found under: {target_dir}"],
                warnings=warnings,
                artifacts=artifacts,
                details={"target_dir": str(target_dir)},
            )
            return finalize(status)

        deps = dependency_map("forge", "slither")
        project_root = find_project_root(target_dir)
        status_snapshot = read_json(STATUS_FILE)
        init_details = status_snapshot.get("init", {}).get("details", {}) if isinstance(status_snapshot, dict) else {}
        run_id = init_details.get("run_id")
        tool_log_parts: List[str] = [f"Project root: {project_root}"]
        external_sections: List[str] = ["=== EXTERNAL CALLS ==="]
        external_calls_present = False

        forge_bin = deps["forge"]
        slither_bin = deps["slither"]
        hardhat_bin = None
        truffle_bin = None
        slither_outputs_present = False

        # Resolve toolchain for non-foundry binaries
        toolchain = init_details.get("toolchain_config") or {}
        if isinstance(toolchain, dict) and toolchain.get("detected_toolchains"):
            tc = ToolchainConfig(
                project_root=project_root,
                detected_toolchains=list(toolchain.get("detected_toolchains", [])),
                binaries={k: v for k, v in toolchain.get("binaries", {}).items() if v},
                preferred_toolchain=str(toolchain.get("preferred_toolchain", "unknown")),
                flatten_available=bool(toolchain.get("flatten_available")),
                storage_layout_available=bool(toolchain.get("storage_layout_available")),
                test_scaffold_family=str(toolchain.get("test_scaffold_family", "generic")),
            )
        else:
            tc = resolve_toolchain(project_root)
            toolchain = tc.to_dict()
        hardhat_bin = tc.binaries.get("hardhat")
        truffle_bin = tc.binaries.get("truffle")

        if slither_bin:
            printer_set, printer_probe = get_slither_printers(slither_bin, cwd=project_root)
            if printer_probe is not None:
                tool_log_parts.append(f"$ {' '.join(printer_probe.command)}\n{printer_probe.stdout}\n{printer_probe.stderr}")
            if not printer_set:
                warnings.append("Could not determine available Slither printers; trying known printer fallbacks.")

            build_result = prepare_slither_build(
                forge_bin=forge_bin,
                hardhat_bin=hardhat_bin,
                truffle_bin=truffle_bin,
                project_root=project_root,
                target_dir=target_dir,
            )
            if build_result is not None:
                tool_log_parts.append(f"$ {' '.join(build_result.command)}\n{build_result.stdout}\n{build_result.stderr}")
                if not build_result.ok:
                    warnings.append("build for slither preparation failed; slither output may be unavailable.")

            printer = choose_slither_printer(
                printer_set,
                "function-summary",
                "entry-points",
                "vars-and-auth",
            )
            if printer is None:
                warnings.append(
                    "Slither does not support any configured state-vector printer "
                    "(candidates: function-summary, entry-points, vars-and-auth)."
                )
            else:
                rendered_output = ""
                for command in slither_command_candidates(
                    slither_bin=slither_bin,
                    printer=printer,
                    project_root=project_root,
                    target_dir=target_dir,
                    prefer_ignore_compile=bool(forge_bin),
                ):
                    result = run_cmd(command, cwd=project_root, timeout=300)
                    tool_log_parts.append(f"$ {' '.join(result.command)}\n{result.stdout}\n{result.stderr}")
                    rendered_output = usable_slither_output(result)
                    if rendered_output:
                        external_sections.append(f"=== SLITHER {printer.upper()} ===")
                        external_sections.append(rendered_output)
                        external_calls_present = True
                        slither_outputs_present = True
                        break
                if not rendered_output:
                    target_label = repo_relative_path(target_dir, project_root)
                    warnings.append(
                        f"slither printer {printer} returned no usable output for {target_label} "
                        "across all invocation strategies."
                    )
        else:
            warnings.append("slither not available; call graph extraction skipped.")

        external_sections.append("\n=== DELEGATECALL CANDIDATES ===")
        delegate_hits, delegate_warnings = collect_delegatecall_hits(files)
        warnings.extend(delegate_warnings)
        external_sections.extend(delegate_hits or ["<none found>"])
        write_text(Path(artifacts["external_calls"]), "\n".join(external_sections) + "\n")

        storage_layouts: Dict[str, Dict[str, object]] = {}
        inspected_contracts: Set[str] = set()
        if forge_bin:
            storage_layouts, layout_warnings, inspected_contracts = inspect_storage_layouts(
                files, forge_bin=forge_bin, project_root=project_root
            )
            warnings.extend(layout_warnings)
            if inspected_contracts and not storage_layouts:
                warnings.append("forge inspect did not produce any usable storage layouts.")
            for contract_name in sorted(inspected_contracts):
                tool_log_parts.append(f"inspect attempted for contract: {contract_name}")
        else:
            warnings.append("forge not available; attempting regex-based storage inference.")
            storage_layouts, layout_warnings, inspected_contracts = infer_storage_layout_from_semantic_index(
                files, project_root
            )
            warnings.extend(layout_warnings)
            if not storage_layouts:
                warnings.append("no storage layout data could be inferred from source.")

        write_text(Path(artifacts["storage_layout"]), json.dumps(storage_layouts, indent=2, sort_keys=True) + "\n")
        write_text(Path(artifacts["invariant_map"]), collect_invariant_candidates(files, project_root))
        write_text(Path(artifacts["tool_log"]), "\n\n".join(tool_log_parts))

        ok = bool(storage_layouts or external_calls_present)
        phase_mode = detect_mode(deps)
        if slither_bin and not slither_outputs_present:
            phase_mode = "degraded"
        if forge_bin and inspected_contracts and not storage_layouts:
            phase_mode = "degraded"
        if not forge_bin and storage_layouts:
            # Regex inference produced something useful
            phase_mode = "degraded"
        has_regex_inference = any(
            v.get("_source") == "regex-inference" for v in storage_layouts.values()
        )
        status = PhaseStatus(
            phase="state_vectors",
            ok=ok,
            mode=phase_mode,
            artifacts=artifacts,
            warnings=warnings,
            errors=errors,
            details={
                "target_dir": str(target_dir),
                "project_root": str(project_root),
                "contracts_inspected": sorted(inspected_contracts),
                "contracts_with_storage_layout": sorted(storage_layouts.keys()),
                "delegatecall_hits": len(delegate_hits),
                "dependencies": deps,
                "run_id": run_id,
                "toolchain_config": toolchain,
                "storage_layout_source": "regex-inference" if has_regex_inference else ("forge-inspect" if forge_bin else "none"),
            },
        )
        return finalize(status)
    except Exception as exc:
        status = fatal_status(
            "state_vectors",
            exc,
            warnings=warnings,
            artifacts=artifacts,
            details={"target_dir": str(target_dir)},
        )
        return finalize(status, exit_code=1)


if __name__ == "__main__":
    raise SystemExit(main())
