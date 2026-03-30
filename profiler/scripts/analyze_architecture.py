from __future__ import annotations

import argparse
import json
import re
from pathlib import Path
from typing import Dict, List, Tuple

from common import (
    AUDIT_DIR,
    STATUS_FILE,
    PhaseStatus,
    ToolchainConfig,
    choose_slither_printer,
    command_output,
    concat_imports,
    dedupe_flattened_solidity,
    dependency_map,
    detect_mode,
    discover_solidity_files,
    extract_contract_declarations,
    extract_imports,
    extract_inheritance,
    fatal_status,
    finalize,
    find_project_root,
    make_failure_status,
    get_slither_printers,
    prepare_slither_build,
    read_json,
    repo_relative_path,
    resolve_toolchain,
    run_cmd,
    select_primary_contract,
    slither_command_candidates,
    usable_slither_output,
    write_text,
)


ROLE_DECL_RE = re.compile(r"\bbytes32\s+public\s+constant\s+([A-Z0-9_]+ROLE)\b")
ONLY_ROLE_FUNC_RE = re.compile(
    r"function\s+([A-Za-z_][A-Za-z0-9_]*)\s*\([^)]*\)([^{};]*?)\{",
    re.MULTILINE | re.DOTALL,
)
ONLY_ROLE_RE = re.compile(r"onlyRole\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)")
ADDRESS_SETTER_RE = re.compile(
    r"function\s+(set[A-Z][A-Za-z0-9_]*)\s*\([^)]*address\s+([A-Za-z_][A-Za-z0-9_]*)",
    re.MULTILINE,
)


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return ""


def parse_scope_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    return [line.strip() for line in read_text(path).splitlines() if line.strip().endswith(".sol")]


def parse_readme_context(project_root: Path) -> Dict[str, object]:
    readme = project_root / "README.md"
    content = read_text(readme)
    scope = parse_scope_lines(project_root / "scope.txt")
    out_of_scope = parse_scope_lines(project_root / "out_of_scope.txt")
    if not content:
        return {
            "readme_present": False,
            "scope_files": scope,
            "out_of_scope_files": out_of_scope,
        }

    lines = content.splitlines()
    trusted_roles: List[str] = []
    in_trusted_roles = False
    main_invariants: List[str] = []
    in_main_invariants = False
    known_issues: List[str] = []
    in_known_issues = False

    for raw in lines:
        line = raw.strip()
        lowered = line.lower()
        if lowered.startswith("## all trusted roles"):
            in_trusted_roles = True
            in_main_invariants = False
            in_known_issues = False
            continue
        if lowered.startswith("## main invariants"):
            in_main_invariants = True
            in_trusted_roles = False
            in_known_issues = False
            continue
        if lowered.startswith("## automated findings") or lowered.startswith("## automated findings / publicly known issues"):
            in_known_issues = True
            in_trusted_roles = False
            in_main_invariants = False
            continue
        if line.startswith("#") and not lowered.startswith("## automated findings") and not lowered.startswith("## all trusted roles") and not lowered.startswith("## main invariants"):
            in_trusted_roles = False
            in_main_invariants = False
            in_known_issues = False
        if in_trusted_roles and line:
            trusted_roles.append(line)
        if in_main_invariants and line and not line.startswith("#"):
            main_invariants.append(line)
        if in_known_issues and (line.startswith("1.") or line.startswith("2.") or line.startswith("- ")):
            known_issues.append(line)

    return {
        "readme_present": True,
        "scope_files": scope,
        "out_of_scope_files": out_of_scope,
        "trusted_roles": trusted_roles,
        "main_invariants": main_invariants,
        "known_issues": known_issues,
        "contest_notes": {
            "requires_readme_as_behavior_source": "README should be treated as the primary behavior reference when contest rules apply.",
            "severity_cap_hint": "Admin-action findings may be severity-capped by contest rules unless resilience to admin action is explicitly promised.",
        },
    }


def collect_privilege_surface(files: List[Path], project_root: Path) -> Tuple[str, Dict[str, object]]:
    role_map: Dict[str, List[str]] = {}
    setter_candidates: List[str] = []

    for path in files:
        content = read_text(path)
        if not content:
            continue
        rel = path.relative_to(project_root).as_posix()
        declared_roles = ROLE_DECL_RE.findall(content)
        for role in declared_roles:
            role_map.setdefault(role, [])
        for match in ONLY_ROLE_FUNC_RE.finditer(content):
            fn_name = match.group(1)
            header = match.group(0)
            roles = ONLY_ROLE_RE.findall(header)
            for role in roles:
                role_map.setdefault(role, []).append(f"{rel}::{fn_name}")
        for match in ADDRESS_SETTER_RE.finditer(content):
            setter_candidates.append(f"{rel}::{match.group(1)}({match.group(2)})")

    lines: List[str] = ["# Privilege Map", ""]
    lines.append("## Role-Gated Functions")
    if role_map:
        for role in sorted(role_map):
            lines.append(f"### {role}")
            entries = sorted(set(role_map[role]))
            if entries:
                lines.extend(f"- {entry}" for entry in entries)
            else:
                lines.append("- Declared, but no direct `onlyRole(...)` hit was extracted.")
            lines.append("")
    else:
        lines.append("Not determined - no role declarations or `onlyRole(...)` gates were extracted.")
        lines.append("")

    lines.append("## Address Setter Candidates")
    if setter_candidates:
        lines.extend(f"- {entry}" for entry in sorted(set(setter_candidates)))
    else:
        lines.append("- None detected.")
    lines.append("")

    summary = {
        "role_map": {role: sorted(set(items)) for role, items in sorted(role_map.items())},
        "address_setter_candidates": sorted(set(setter_candidates)),
    }
    return "\n".join(lines).rstrip() + "\n", summary


def build_fallback_topology(files: List[Path], project_root: Path, primary: Path | None) -> str:
    lines: List[str] = []
    lines.append("=== FILE INVENTORY ===")
    lines.append(f"Solidity files discovered: {len(files)}")
    if primary:
        try:
            primary_rel = primary.relative_to(project_root).as_posix()
        except ValueError:
            primary_rel = str(primary)
        lines.append(f"Primary contract candidate: {primary_rel}")
    lines.append("")

    lines.append("=== CONTRACT DECLARATIONS ===")
    for path in files:
        declarations = extract_contract_declarations(path)
        if not declarations:
            continue
        try:
            rel = path.relative_to(project_root).as_posix()
        except ValueError:
            rel = str(path)
        rendered = ", ".join(f"{item['kind']} {item['name']}" for item in declarations)
        lines.append(f"{rel}: {rendered}")
    lines.append("")

    inheritance_lines: List[str] = []
    for path in files:
        try:
            rel = path.relative_to(project_root).as_posix()
        except ValueError:
            rel = str(path)
        for contract_name, parents in extract_inheritance(path):
            if parents:
                inheritance_lines.append(f"{rel}: {contract_name} -> {', '.join(parents)}")
    lines.append("=== INHERITANCE EDGES ===")
    lines.extend(inheritance_lines or ["<none detected>"])
    lines.append("")

    import_lines: List[str] = []
    for path in files:
        imports = extract_imports(path)
        if not imports:
            continue
        try:
            rel = path.relative_to(project_root).as_posix()
        except ValueError:
            rel = str(path)
        import_lines.append(f"{rel}:")
        import_lines.extend(f"  - {item}" for item in imports[:12])
        if len(imports) > 12:
            import_lines.append(f"  - ... {len(imports) - 12} more")
    lines.append("=== IMPORT GRAPH (TRUNCATED PER FILE) ===")
    lines.extend(import_lines or ["<none detected>"])
    lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze contract architecture.")
    parser.add_argument("--target-dir", required=True, help="Directory containing Solidity contracts.")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    target_dir = Path(args.target_dir).resolve()
    warnings: List[str] = []
    errors: List[str] = []
    artifacts = {
        "flattened": str(AUDIT_DIR / "context_flattened.sol"),
        "topology": str(AUDIT_DIR / "topology_map.txt"),
        "contest_context": str(AUDIT_DIR / "contest_context.json"),
        "privilege_map": str(AUDIT_DIR / "privilege_map.md"),
        "tool_log": str(AUDIT_DIR / "phase1_tooling.log"),
    }

    try:
        if not target_dir.exists() or not target_dir.is_dir():
            status = make_failure_status(
                "architecture",
                errors=[f"Target directory does not exist or is not a directory: {target_dir}"],
                warnings=warnings,
                artifacts=artifacts,
                details={"target_dir": str(target_dir)},
            )
            return finalize(status)

        files = discover_solidity_files(target_dir)
        if not files:
            status = make_failure_status(
                "architecture",
                errors=[f"No Solidity files found under: {target_dir}"],
                warnings=warnings,
                artifacts=artifacts,
                details={"target_dir": str(target_dir)},
            )
            return finalize(status)

        primary = select_primary_contract(files)
        project_root = find_project_root(target_dir)
        status_snapshot = read_json(STATUS_FILE)
        init_details = status_snapshot.get("init", {}).get("details", {}) if isinstance(status_snapshot, dict) else {}
        run_id = init_details.get("run_id")
        toolchain = init_details.get("toolchain_config") or {}
        deps = dependency_map("forge", "slither")
        tool_log_parts: List[str] = [
            f"Discovered {len(files)} Solidity file(s).",
            f"Project root: {project_root}",
            f"Primary contract: {primary}",
        ]

        # Re-resolve toolchain for full binary map (covers hardhat/truffle discovered at init)
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

        flattened_content = ""
        forge_bin = deps["forge"]
        slither_bin = deps["slither"]
        hardhat_bin = tc.binaries.get("hardhat")
        truffle_bin = tc.binaries.get("truffle")
        slither_outputs_present = False

        if forge_bin and primary and "foundry" in tc.detected_toolchains:
            result = run_cmd([forge_bin, "flatten", str(primary)], cwd=project_root, timeout=180)
            tool_log_parts.append(f"$ {' '.join(result.command)}\n{result.stdout}\n{result.stderr}")
            if result.ok and result.stdout.strip():
                flattened_content = dedupe_flattened_solidity(result.stdout)
            else:
                warnings.append("forge flatten failed; using import-graph concatenation.")
                flattened_content = concat_imports(primary, project_root)
                warnings.append("flattened context produced via import-graph concatenation.")
        elif primary:
            warnings.append("forge not available; using import-graph concatenation.")
            flattened_content = concat_imports(primary, project_root)
            warnings.append("flattened context produced via import-graph concatenation.")
        else:
            warnings.append("no primary contract detected; flattened context unavailable.")

        write_text(Path(artifacts["flattened"]), flattened_content)

        if slither_bin:
            printer_set, printer_probe = get_slither_printers(slither_bin, cwd=project_root)
            if printer_probe is not None:
                tool_log_parts.append(f"$ {' '.join(printer_probe.command)}\n{printer_probe.stdout}\n{printer_probe.stderr}")
            if not printer_set:
                warnings.append("Could not determine available Slither printers; trying known printer fallbacks.")
        else:
            printer_set = set()

        if slither_bin:
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

        topology_sections: List[str] = []
        if slither_bin:
            for label, candidates in (
                ("CONTRACT SUMMARY", ("contract-summary", "human-summary")),
                ("MODIFIERS", ("modifiers", "modifiers-order")),
                ("REQUIRES", ("require",)),
            ):
                printer = choose_slither_printer(printer_set, *candidates)
                if not printer:
                    warnings.append(
                        f"Slither does not support any configured printer for {label.lower()} "
                        f"(candidates: {', '.join(candidates)})."
                    )
                    continue

                rendered_output = ""
                attempts = slither_command_candidates(
                    slither_bin=slither_bin,
                    printer=printer,
                    project_root=project_root,
                    target_dir=target_dir,
                    prefer_ignore_compile=bool(forge_bin),
                )
                for command in attempts:
                    result = run_cmd(command, cwd=project_root, timeout=300)
                    tool_log_parts.append(f"$ {' '.join(result.command)}\n{result.stdout}\n{result.stderr}")
                    rendered_output = usable_slither_output(result)
                    if rendered_output:
                        topology_sections.append(f"=== {label} ({printer}) ===\n{rendered_output}\n")
                        slither_outputs_present = True
                        break
                if not rendered_output:
                    target_label = repo_relative_path(target_dir, project_root)
                    warnings.append(
                        f"slither printer {printer} returned no usable output for {target_label} "
                        "across all invocation strategies."
                    )
        else:
            warnings.append("slither not available; topology extraction degraded.")

        if not topology_sections:
            topology_sections.append(build_fallback_topology(files, project_root, primary))
            warnings.append("Using source-derived fallback topology because slither output was unavailable.")

        contest_context = parse_readme_context(project_root)
        privilege_map_md, privilege_summary = collect_privilege_surface(files, project_root)

        write_text(Path(artifacts["topology"]), "\n".join(topology_sections))
        write_text(
            Path(artifacts["contest_context"]),
            json.dumps(
                {
                    **contest_context,
                    "primary_contract": str(primary) if primary else None,
                    "target_dir": str(target_dir),
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
        )
        write_text(Path(artifacts["privilege_map"]), privilege_map_md)
        write_text(Path(artifacts["tool_log"]), "\n\n".join(tool_log_parts))

        ok = bool(flattened_content.strip() or topology_sections)
        phase_mode = detect_mode(deps)
        if slither_bin and not slither_outputs_present:
            phase_mode = "degraded"
        status = PhaseStatus(
            phase="architecture",
            ok=ok,
            mode=phase_mode,
            artifacts=artifacts,
            warnings=warnings,
            errors=errors,
            details={
                "target_dir": str(target_dir),
                "project_root": str(project_root),
                "solidity_file_count": len(files),
                "primary_contract": str(primary) if primary else None,
                "scope_file_count": len(contest_context.get("scope_files", [])) if isinstance(contest_context, dict) else 0,
                "roles_detected": sorted(privilege_summary.get("role_map", {}).keys()),
                "dependencies": deps,
                "run_id": run_id,
                "toolchain_config": toolchain,
            },
        )
        return finalize(status)
    except Exception as exc:
        status = fatal_status(
            "architecture",
            exc,
            warnings=warnings,
            artifacts=artifacts,
            details={"target_dir": str(target_dir)},
        )
        return finalize(status, exit_code=1)


if __name__ == "__main__":
    raise SystemExit(main())
