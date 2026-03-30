"""
cerberus_common.toolchain — Toolchain detection and command execution.

Initializes SKILL_ROOT and SKILL_ROOT-dependent paths (delegated to types.py),
then provides binary resolution, subprocess execution, and Slither integration.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
from glob import glob as _glob
from hashlib import sha1
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence, Set, Tuple

from . import types as _t
from .types import PROJECT_MARKERS  # re-export for consumers of toolchain.py

# ── SKILL_ROOT initialization ──────────────────────────────────────────────────

_SKILL_ROOT_VALUE: Optional[Path] = None


def set_skill_root(root: Path) -> None:
    """Must be called once at startup by every skill script."""
    global _SKILL_ROOT_VALUE
    _SKILL_ROOT_VALUE = root.resolve()
    _t._ensure_paths(root)


def get_skill_root() -> Path:
    """Return the skill root, or derive it from this file's location."""
    global _SKILL_ROOT_VALUE
    if _SKILL_ROOT_VALUE is not None:
        return _SKILL_ROOT_VALUE
    # Derive from this file's location: cerberus_common/toolchain.py -> cerberus-common/ -> skill root
    return Path(__file__).resolve().parent.parent


# ── Path accessors (forwarded from types.py) ──────────────────────────────────

def SKILL_ROOT() -> Path:
    return get_skill_root()


def AUDIT_DIR() -> Path:
    return _t.AUDIT_DIR


def STATUS_FILE() -> Path:
    return _t.STATUS_FILE


def META_DIR() -> Path:
    return _t.META_DIR


def IMPROVEMENT_LOG_FILE() -> Path:
    return _t.IMPROVEMENT_LOG_FILE


def IMPROVEMENT_SUMMARY_FILE() -> Path:
    return _t.IMPROVEMENT_SUMMARY_FILE


def IMPROVEMENT_HOTSPOTS_FILE() -> Path:
    return _t.IMPROVEMENT_HOTSPOTS_FILE


def RESOLVED_HOTSPOTS_FILE() -> Path:
    return _t.RESOLVED_HOTSPOTS_FILE


# ── Binary resolution ──────────────────────────────────────────────────────────

def which(binary: str) -> Optional[str]:
    resolved = shutil.which(binary)
    if resolved:
        return resolved

    home = Path.home()
    fallback_paths = (
        home / ".foundry" / "bin" / binary,
        home / ".cargo" / "bin" / binary,
        home / ".local" / "bin" / binary,
        home / ".npm" / "global" / "bin" / binary,
        Path(".venv") / "bin" / binary,
        Path("node_modules") / ".bin" / binary,
    )
    for candidate in fallback_paths:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)

    nvm_versions = home / ".nvm" / "versions" / "node"
    if nvm_versions.is_dir():
        try:
            latest = sorted(nvm_versions.iterdir(), key=lambda p: p.name, reverse=True)
            for version_dir in latest:
                if version_dir.is_dir():
                    nvm_bin = version_dir / "bin" / binary
                    if nvm_bin.is_file() and os.access(nvm_bin, os.X_OK):
                        return str(nvm_bin)
                    break
        except OSError:
            pass
    return None


def _resolve_npm_binary(project_root: Path, binary: str) -> Optional[str]:
    """Resolve an npm-installed binary (hardhat, truffle, etc.) from node_modules."""
    candidates = [
        project_root / "node_modules" / ".bin" / binary,
        Path(".venv") / "bin" / binary,
    ]
    home = Path.home()
    candidates.append(home / ".npm" / "global" / "bin" / binary)
    nvm_versions = home / ".nvm" / "versions" / "node"
    if nvm_versions.is_dir():
        try:
            for version_dir in sorted(nvm_versions.iterdir(), key=lambda p: p.name, reverse=True):
                if version_dir.is_dir():
                    candidates.append(version_dir / "bin" / binary)
                    break
        except OSError:
            pass
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    resolved = shutil.which(binary)
    if resolved:
        return resolved
    return None


# ── Subprocess execution ───────────────────────────────────────────────────────

_MAX_CMD_OUTPUT_CHARS = 512 * 1024  # 512 KB per command output


def run_cmd(
    args: Sequence[str],
    *,
    cwd: Optional[Path] = None,
    timeout: int = 120,
) -> _t.CommandResult:
    try:
        proc = subprocess.run(
            list(args),
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return _t.CommandResult(
            command=list(args),
            returncode=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
        )
    except subprocess.TimeoutExpired as exc:
        def _decode(val: object) -> str:
            if isinstance(val, str):
                return val
            if isinstance(val, (bytes, bytearray)):
                return val.decode("utf-8", errors="replace")
            return ""
        stdout = _decode(exc.stdout)
        stderr = _decode(exc.stderr)
        timeout_msg = f"Command timed out after {timeout}s."
        stderr = f"{stderr}\n{timeout_msg}".strip()
        return _t.CommandResult(
            command=list(args),
            returncode=124,
            stdout=stdout,
            stderr=stderr,
            timed_out=True,
        )
    except OSError as exc:
        return _t.CommandResult(
            command=list(args),
            returncode=1,
            stdout="",
            stderr=f"Failed to execute command: {exc}",
        )


def command_output(result: _t.CommandResult) -> str:
    stdout = result.stdout.strip()
    raw = stdout if stdout else result.stderr.strip()
    if len(raw) > _MAX_CMD_OUTPUT_CHARS:
        half = _MAX_CMD_OUTPUT_CHARS // 2
        raw = raw[:half] + "\n... [truncated] ...\n" + raw[-half:]
    return raw


# ── Slither helpers ────────────────────────────────────────────────────────────

_SLITHER_NOISE_PATTERNS = (
    "warning:slither:no contract was analyzed",
    "info:slither:. analyzed (0 contracts)",
)


def is_noise_only_slither_output(raw: str) -> bool:
    lowered = raw.strip().lower()
    if not lowered:
        return True
    return all(pattern in lowered for pattern in _SLITHER_NOISE_PATTERNS)


def usable_slither_output(result: _t.CommandResult) -> str:
    raw = command_output(result)
    if not raw or is_noise_only_slither_output(raw):
        return ""
    return raw


def parse_slither_printers(raw_output: str) -> set[str]:
    printers: set[str] = set()
    for line in raw_output.splitlines():
        stripped = line.strip()
        if not stripped.startswith("|"):
            continue
        parts = [part.strip() for part in stripped.strip("|").split("|")]
        if len(parts) < 3:
            continue
        printer = parts[1]
        if not printer or printer.lower() == "printer":
            continue
        printers.add(printer)
    return printers


def get_slither_printers(slither_bin: Optional[str], *, cwd: Path) -> tuple[set[str], Optional[_t.CommandResult]]:
    if not slither_bin:
        return set(), None
    result = run_cmd([slither_bin, "--list-printers"], cwd=cwd, timeout=120)
    return parse_slither_printers(command_output(result)), result


def choose_slither_printer(available: set[str], *candidates: str) -> Optional[str]:
    if not candidates:
        return None
    if not available:
        return candidates[0]
    for candidate in candidates:
        if candidate in available:
            return candidate
    return None


def slither_command_candidates(
    *,
    slither_bin: str,
    printer: str,
    project_root: Path,
    target_dir: Path,
    prefer_ignore_compile: bool,
) -> List[List[str]]:
    target_arg = repo_relative_path(target_dir, project_root)
    targets: List[str] = ["."]
    if target_arg not in ("", "."):
        targets.append(target_arg)

    commands: List[List[str]] = []
    seen: set[tuple[str, ...]] = set()
    variants = [True, False] if prefer_ignore_compile else [False]

    for ignore_compile in variants:
        for target in targets:
            command = [slither_bin, target]
            if ignore_compile:
                command.append("--ignore-compile")
            command.extend(["--print", printer])
            key = tuple(command)
            if key in seen:
                continue
            seen.add(key)
            commands.append(command)
    return commands


def detect_mode(dependencies: Mapping[str, Optional[str]]) -> str:
    return "full" if all(dependencies.values()) else "degraded"


def dependency_map(*binaries: str) -> Dict[str, Optional[str]]:
    return {binary: which(binary) for binary in binaries}


# ── Project root / toolchain detection ─────────────────────────────────────────

def find_project_root(start: Path) -> Path:
    current = start.resolve()
    if current.is_file():
        current = current.parent

    for candidate in (current, *current.parents):
        for toolchain, markers in _t.PROJECT_MARKERS.items():
            for marker in markers:
                if (candidate / marker).exists():
                    return candidate
        if (candidate / ".git").exists():
            return candidate
        if candidate == candidate.parent:
            break
    return current


def resolve_toolchain(project_root: Path) -> _t.ToolchainConfig:
    detected_toolchains: List[str] = []
    binaries: Dict[str, Optional[str]] = {}

    current = project_root.resolve()
    if current.is_file():
        current = current.parent

    for candidate in (current, *current.parents):
        for toolchain, markers in _t.PROJECT_MARKERS.items():
            for marker in markers:
                if (candidate / marker).exists():
                    if toolchain not in detected_toolchains:
                        detected_toolchains.append(toolchain)
                    break
        if (candidate / ".git").exists():
            if "bare" not in detected_toolchains:
                detected_toolchains.append("bare")
            break
        if candidate == candidate.parent:
            break

    forge_bin = which("forge")
    slither_bin = which("slither")
    solc_bin = which("solc")
    hardhat_bin = _resolve_npm_binary(project_root, "hardhat")
    truffle_bin = _resolve_npm_binary(project_root, "truffle")
    brownie_bin = which("brownie")
    anchor_bin = which("anchor")

    binaries["forge"] = forge_bin
    binaries["slither"] = slither_bin
    binaries["solc"] = solc_bin
    binaries["hardhat"] = hardhat_bin
    binaries["truffle"] = truffle_bin
    binaries["brownie"] = brownie_bin
    binaries["anchor"] = anchor_bin

    preferred = "unknown"
    if "foundry" in detected_toolchains and forge_bin:
        preferred = "foundry"
    elif "hardhat" in detected_toolchains and hardhat_bin:
        preferred = "hardhat"
    elif "truffle" in detected_toolchains and truffle_bin:
        preferred = "truffle"
    elif "brownie" in detected_toolchains and brownie_bin:
        preferred = "brownie"
    elif "anchor" in detected_toolchains and anchor_bin:
        preferred = "anchor"
    elif forge_bin and slither_bin:
        preferred = "bare"
    elif forge_bin:
        preferred = "bare"
    elif hardhat_bin:
        preferred = "hardhat"
    elif slither_bin or solc_bin:
        preferred = "bare"

    test_family = "generic"
    if preferred == "foundry":
        test_family = "foundry"
    elif preferred in ("hardhat", "truffle"):
        test_family = "hardhat"

    return _t.ToolchainConfig(
        project_root=project_root,
        detected_toolchains=detected_toolchains,
        binaries=binaries,
        preferred_toolchain=preferred,
        flatten_available=bool(forge_bin and "foundry" in detected_toolchains),
        storage_layout_available=bool(forge_bin and "foundry" in detected_toolchains),
        test_scaffold_family=test_family,
    )


# ── Path utilities ─────────────────────────────────────────────────────────────

def safe_repo_relative_path(raw_path: str) -> str:
    if "\x00" in raw_path:
        raise ValueError("Contract path must not contain null bytes.")
    normalized = os.path.normpath(raw_path).replace("\\", "/")
    if normalized in (".", ""):
        raise ValueError("Contract path must not be empty.")
    if normalized.startswith("../") or normalized == ".." or normalized.startswith("/") or "/../" in normalized:
        raise ValueError(f"Unsafe contract path: {raw_path}")
    if ".." in normalized.split("/"):
        raise ValueError(f"Unsafe contract path: {raw_path}")
    if not normalized.endswith(".sol"):
        raise ValueError(f"Contract path must point to a .sol file: {raw_path}")
    return normalized


def discover_solidity_files(target_dir: Path) -> List[Path]:
    return sorted(
        [path for path in target_dir.rglob("*.sol") if path.is_file()],
        key=lambda path: (len(path.parts), path.name.lower(), str(path).lower()),
    )


def repo_relative_path(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return str(path)


def file_exists_within(root: Path, relative_path: str) -> bool:
    return (root / relative_path).is_file()


# ── Slither build preparation ───────────────────────────────────────────────────

def prepare_slither_build(
    *,
    forge_bin: Optional[str],
    hardhat_bin: Optional[str] = None,
    truffle_bin: Optional[str] = None,
    project_root: Path,
    target_dir: Path,
    timeout: int = 300,
) -> Optional[_t.CommandResult]:
    target_arg = repo_relative_path(target_dir, project_root)

    if forge_bin:
        args: List[str] = [forge_bin, "build", "--build-info"]
        if target_arg not in ("", "."):
            args.append(target_arg)
        return run_cmd(args, cwd=project_root, timeout=timeout)

    if hardhat_bin:
        return run_cmd([hardhat_bin, "compile"], cwd=project_root, timeout=timeout)

    if truffle_bin:
        return run_cmd([truffle_bin, "compile"], cwd=project_root, timeout=timeout)

    return None
