from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import textwrap
import importlib.util
from pathlib import Path


# scripts live under cerberus-proof-auditor/resources/ (not meta/)
SKILL_RESOURCES = Path(__file__).resolve().parent.parent / "resources"
ANALYZE_ARCHITECTURE = SKILL_RESOURCES / "analyze_architecture.py"
COMMON = SKILL_RESOURCES / "common.py"
RULE_SCAN = SKILL_RESOURCES / "rule_scan.py"
SCAFFOLD_TESTS = SKILL_RESOURCES / "scaffold_tests.py"
INIT_WORKSPACE = SKILL_RESOURCES / "init_workspace.py"
PREFLIGHT = SKILL_RESOURCES / "preflight_or_repair.py"
SEMANTIC_INDEX = SKILL_RESOURCES / "build_semantic_index.py"
EXTRACT_ACTIONS = SKILL_RESOURCES / "extract_actions.py"
AUTHORITY_GRAPH = SKILL_RESOURCES / "build_authority_graph.py"
DEPENDENCY_GRAPH = SKILL_RESOURCES / "build_dependency_graph.py"
MINE_INVARIANTS = SKILL_RESOURCES / "mine_invariants.py"
GENERATE_FINDINGS = SKILL_RESOURCES / "generate_finding_candidates.py"
CONFIRM_FINDINGS = SKILL_RESOURCES / "confirm_findings.py"
PLAN_PROOFS = SKILL_RESOURCES / "plan_proofs.py"
TRIAGE_HYPOTHESES = SKILL_RESOURCES / "triage_hypotheses.py"
DESIGN_POC = SKILL_RESOURCES / "design_poc.py"


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader, f"Could not locate module: {path}"
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault(name, module)
    spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def build_hardhat_fixture(root: Path) -> None:
    """Build a minimal Hardhat-style fixture for non-Foundry regression tests."""
    write(
        root / "hardhat.config.js",
        textwrap.dedent(
            """
            module.exports = {
                solidity: '0.8.20',
            };
            """
        ).strip()
        + "\n",
    )
    write(
        root / "package.json",
        '{"name":"test","scripts":{"compile":"hardhat compile"},"dependencies":{}}\n',
    )
    write(
        root / "src" / "Vault.sol",
        textwrap.dedent(
            """
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;

            contract Vault {
                address public owner;
                mapping(address => uint256) public balances;

                constructor() {
                    owner = msg.sender;
                }

                function deposit() external payable {
                    balances[msg.sender] += msg.value;
                }

                function withdraw(uint256 amount) external {
                    require(balances[msg.sender] >= amount, "insufficient balance");
                    balances[msg.sender] -= amount;
                    payable(msg.sender).transfer(amount);
                }

                function sweep() external {
                    require(msg.sender == owner, "not owner");
                    payable(msg.sender).transfer(address(this).balance);
                }
            }
            """
        ).strip()
        + "\n",
    )
    for name in ("01_threat_model.md", "02_static_analysis.md", "03_attack_vectors.md"):
        write(root / ".audit_board" / name, "# Seed\n\n- substantive fixture entry\n")


def build_bare_solc_fixture(root: Path) -> None:
    """Build a minimal Solidity project with no build config (bare solc)."""
    write(
        root / "src" / "Vault.sol",
        textwrap.dedent(
            """
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;

            contract Vault {
                address public owner;
                mapping(address => uint256) public balances;

                constructor() {
                    owner = msg.sender;
                }

                function deposit() external payable {
                    balances[msg.sender] += msg.value;
                }

                function withdraw(uint256 amount) external {
                    require(balances[msg.sender] >= amount, "insufficient balance");
                    balances[msg.sender] -= amount;
                    payable(msg.sender).transfer(amount);
                }

                function sweep() external {
                    require(msg.sender == owner, "not owner");
                    payable(msg.sender).transfer(address(this).balance);
                }
            }
            """
        ).strip()
        + "\n",
    )
    write(
        root / "src" / "Manager.sol",
        textwrap.dedent(
            """
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;

            contract Manager {
                address public governor;
                address public pendingGovernor;

                constructor(address _governor) {
                    governor = _governor;
                }

                function proposeGovernor(address newGovernor) external {
                    require(msg.sender == governor, "not governor");
                    pendingGovernor = newGovernor;
                }

                function acceptGovernor() external {
                    require(msg.sender == pendingGovernor, "not pending");
                    governor = msg.sender;
                    pendingGovernor = address(0);
                }
            }
            """
        ).strip()
        + "\n",
    )
    for name in ("01_threat_model.md", "02_static_analysis.md", "03_attack_vectors.md"):
        write(root / ".audit_board" / name, "# Seed\n\n- substantive fixture entry\n")


def build_fixture(root: Path) -> None:
    write(
        root / "foundry.toml",
        textwrap.dedent(
            """
            [profile.default]
            src = "src"
            out = "out"
            libs = []
            """
        ).strip()
        + "\n",
    )

    write(
        root / "src" / "EVault" / "IEVault.sol",
        textwrap.dedent(
            """
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;

            interface IEVault {
                function totalAssets() external view returns (uint256);
            }
            """
        ).strip()
        + "\n",
    )

    write(
        root / "src" / "EVault" / "shared" / "Base.sol",
        textwrap.dedent(
            """
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;

            abstract contract Base {
                function meaning() internal pure returns (uint256) {
                    return 42;
                }
            }
            """
        ).strip()
        + "\n",
    )

    write(
        root / "src" / "EVault" / "Dispatch.sol",
        textwrap.dedent(
            """
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;

            import {Base} from "./shared/Base.sol";

            abstract contract Dispatch is Base {
                function route() internal pure returns (uint256) {
                    return meaning();
                }
            }
            """
        ).strip()
        + "\n",
    )

    write(
        root / "src" / "EVault" / "EVault.sol",
        textwrap.dedent(
            """
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;

            import {Dispatch} from "./Dispatch.sol";

            contract EVault is Dispatch {
                function totalAssets() external pure returns (uint256) {
                    return route();
                }
            }
            """
        ).strip()
        + "\n",
    )

    write(
        root / "src" / "test" / "MockVault.sol",
        textwrap.dedent(
            """
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.0;

            contract MockVault {}
            """
        ).strip()
        + "\n",
    )

    write(
        root / "src" / "Manager.sol",
        textwrap.dedent(
            """
            // SPDX-License-Identifier: MIT
            pragma solidity ^0.8.20;

            contract Manager {
                bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");
                address public treasury;
                address public registry;

                function setTreasury(address newTreasury) external {
                    treasury = newTreasury;
                }

                function rotateRegistry(address newRegistry) external {
                    registry = newRegistry;
                }

                function recoverAssets(address token) external {
                    treasury = token;
                }

                function rescueToken(address token) external {
                    treasury = token;
                }
            }
            """
        ).strip()
        + "\n",
    )

    for name in ("01_threat_model.md", "02_static_analysis.md", "03_attack_vectors.md"):
        write(root / ".audit_board" / name, "# Seed\n\n- substantive fixture entry\n")


def run_architecture_eval() -> None:
    with tempfile.TemporaryDirectory(prefix="cerberus-auditor-eval-") as raw_tmp:
        root = Path(raw_tmp)
        build_fixture(root)

        proc = subprocess.run(
            [sys.executable, str(ANALYZE_ARCHITECTURE), "--target-dir", "src"],
            cwd=str(root),
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if proc.returncode != 0:
            raise AssertionError(
                "architecture phase exited non-zero during regression eval\n"
                f"stdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}"
            )

        try:
            payload = json.loads(proc.stdout)
        except json.JSONDecodeError as exc:
            raise AssertionError(f"architecture phase did not emit valid JSON: {exc}\n{proc.stdout}") from exc

        details = payload.get("details", {})
        primary = str(details.get("primary_contract", ""))
        if not primary.endswith("src/EVault/EVault.sol"):
            raise AssertionError(f"expected EVault.sol as primary contract, got: {primary}")

        if not payload.get("ok"):
            raise AssertionError(f"expected architecture phase ok=true, got payload: {json.dumps(payload, indent=2)}")

        topology = (root / ".audit_board" / "topology_map.txt").read_text(encoding="utf-8")
        if "EVault" not in topology or "Dispatch" not in topology:
            raise AssertionError(f"topology artifact missing expected contract context:\n{topology}")


def run_skip_filter_eval() -> None:
    """Verify should_skip_storage_layout_file correctly gates excluded directories."""
    _mod = load_module("extract_state_vectors", SKILL_RESOURCES / "extract_state_vectors.py")
    skip = _mod.should_skip_storage_layout_file

    should_skip = [
        Path("src/test/Foo.sol"),
        Path("src/interfaces/IFoo.sol"),
        Path("src/interface/IBar.sol"),
        Path("src/mock/MockFoo.sol"),
        Path("src/mocks/MockBar.sol"),
        Path("src/script/Deploy.sol"),
        Path("src/scripts/Deploy.sol"),
        Path("src/Foo.t.sol"),
    ]
    should_keep = [
        Path("src/Vault.sol"),
        Path("src/EVault/EVault.sol"),
        Path("src/core/Router.sol"),
    ]

    for p in should_skip:
        if not skip(p):
            raise AssertionError(f"Expected skip for {p}, but was not skipped")
    for p in should_keep:
        if skip(p):
            raise AssertionError(f"Expected keep for {p}, but was skipped")


def run_quality_gate_eval() -> None:
    common = load_module("cerberus_common_eval", COMMON)
    with tempfile.TemporaryDirectory(prefix="cerberus-auditor-quality-") as raw_tmp:
        root = Path(raw_tmp)
        audit_dir = root / ".audit_board"
        audit_dir.mkdir(parents=True, exist_ok=True)
        for name in ("01_threat_model.md", "02_static_analysis.md", "03_attack_vectors.md"):
            write(audit_dir / name, "# Heading\n\n## Section\n")

        previous = Path.cwd()
        os.chdir(root)
        try:
            status = common.PhaseStatus(
                phase="state_vectors",
                ok=True,
                mode="full",
                artifacts={},
                warnings=[],
                errors=[],
                details={},
            )
            validated = common.validate_phase_outputs(status)
            if validated.ok:
                raise AssertionError("Expected quality gate to reject empty markdown artifacts")
        finally:
            os.chdir(previous)


def run_rule_scan_signal_eval() -> None:
    common = load_module("cerberus_common_signal_eval", COMMON)
    rule_scan = load_module("cerberus_rule_scan_eval", RULE_SCAN)

    code = textwrap.dedent(
        """
        contract Demo {
            // delegatecall(address(this), data);
            function run(address target, bytes memory data) external {
                (bool ok,) = target.delegatecall(data);
                require(ok);
            }
        }
        """
    )
    stripped = common.strip_solidity_comments(code)
    if "delegatecall(address(this), data)" in stripped:
        raise AssertionError("Expected comment stripping to remove comment-only delegatecall text")

    edge = {
        "id": "delegatecall-storage-collision",
        "severity": "high",
        "description": "delegatecall heuristic",
        "pattern": r"delegatecall\s*\(",
    }
    no_evidence = rule_scan.score_exploit_family(edge, Path("src/Demo.sol"), stripped, evidence_tokens=[])
    if no_evidence is not None:
        raise AssertionError("Expected exploit family scoring to require corroborating evidence")
    with_evidence = rule_scan.score_exploit_family(
        edge,
        Path("src/Demo.sol"),
        stripped,
        evidence_tokens=["rule:unchecked-return", "concrete-contract"],
    )
    if with_evidence is None or with_evidence["confidence"] < 2:
        raise AssertionError("Expected evidence-backed exploit family scoring to succeed")


def run_scaffold_hint_eval() -> None:
    scaffold = load_module("cerberus_scaffold_eval", SCAFFOLD_TESTS)
    with tempfile.TemporaryDirectory(prefix="cerberus-auditor-scaffold-") as raw_tmp:
        root = Path(raw_tmp)
        write(
            root / "src" / "Manager.sol",
            textwrap.dedent(
                """
                // SPDX-License-Identifier: MIT
                pragma solidity ^0.8.20;

                contract Manager {
                    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");

                    function setTreasury(address newTreasury) external {}
                    function rescueToken(address token) external {}
                }
                """
            ).strip()
            + "\n",
        )
        audit_dir = root / ".audit_board"
        audit_dir.mkdir(parents=True, exist_ok=True)
        previous = Path.cwd()
        os.chdir(root)
        try:
            context = scaffold.load_context_lines("Manager", "src/Manager.sol")
            if "TREASURY_ROLE" not in context["roles"]:
                raise AssertionError("Expected scaffold context to extract role constants")
            if "setTreasury" not in context["setters"]:
                raise AssertionError("Expected scaffold context to extract setter functions")
            if "rescueToken" not in context["sinks"]:
                raise AssertionError("Expected scaffold context to extract sink functions")
        finally:
            os.chdir(previous)


def _run_json_command(root: Path, command: list[str], *, expect_ok: bool = True) -> dict:
    proc = subprocess.run(
        command,
        cwd=str(root),
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    if expect_ok and proc.returncode != 0:
        raise AssertionError(
            "command exited non-zero during regression eval\n"
            f"cmd: {' '.join(command)}\nstdout:\n{proc.stdout}\n\nstderr:\n{proc.stderr}"
        )
    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise AssertionError(f"command did not emit valid JSON: {' '.join(command)}\n{proc.stdout}") from exc


def run_structured_pipeline_eval() -> None:
    with tempfile.TemporaryDirectory(prefix="cerberus-proof-auditor-pipeline-") as raw_tmp:
        root = Path(raw_tmp)
        build_fixture(root)
        write(
            root / "test" / "Base.t.sol",
            textwrap.dedent(
                """
                // SPDX-License-Identifier: MIT
                pragma solidity ^0.8.20;

                import "forge-std/Test.sol";

                contract BaseTest is Test {
                    function setUp() public virtual {}
                }
                """
            ).strip()
            + "\n",
        )

        payload = _run_json_command(root, [sys.executable, str(INIT_WORKSPACE), "--target-dir", "src"])
        if payload.get("phase") != "init" or not payload.get("ok"):
            raise AssertionError(f"expected init ok=true, got: {json.dumps(payload, indent=2)}")

        payload = _run_json_command(
            root,
            [
                sys.executable,
                str(PREFLIGHT),
                "--phase-name",
                "semantic_index",
                "--script-path",
                str(SEMANTIC_INDEX),
                "--target-dir",
                "src",
            ],
        )
        if payload.get("phase") != "preflight_or_repair" or payload.get("details", {}).get("decision") != "resume":
            raise AssertionError(f"expected preflight decision=resume, got: {json.dumps(payload, indent=2)}")

        for script in (
            SEMANTIC_INDEX,
            EXTRACT_ACTIONS,
            AUTHORITY_GRAPH,
            DEPENDENCY_GRAPH,
            MINE_INVARIANTS,
            GENERATE_FINDINGS,
            CONFIRM_FINDINGS,
            PLAN_PROOFS,
            TRIAGE_HYPOTHESES,
        ):
            payload = _run_json_command(root, [sys.executable, str(script), "--target-dir", "src"])
            if not payload.get("ok"):
                raise AssertionError(f"expected {script.name} ok=true, got: {json.dumps(payload, indent=2)}")

        payload = _run_json_command(root, [sys.executable, str(DESIGN_POC), "--finding-id", "unguarded-sink-rescueToken"])
        if payload.get("phase") != "poc_design" or not payload.get("ok"):
            raise AssertionError(f"expected poc_design ok=true, got: {json.dumps(payload, indent=2)}")

        semantic = json.loads((root / ".audit_board" / "semantic_index.json").read_text(encoding="utf-8"))
        if not semantic.get("contracts"):
            raise AssertionError("semantic_index.json did not contain contracts")

        actions = json.loads((root / ".audit_board" / "action_catalog.json").read_text(encoding="utf-8"))
        if not actions.get("actions"):
            raise AssertionError("action_catalog.json did not contain actions")

        authority = json.loads((root / ".audit_board" / "authority_graph.json").read_text(encoding="utf-8"))
        if "sinks" not in authority:
            raise AssertionError("authority_graph.json missing sinks")

        findings = json.loads((root / ".audit_board" / "finding_candidates.json").read_text(encoding="utf-8"))
        if not findings.get("findings"):
            raise AssertionError("finding_candidates.json did not contain findings")

        confirmations = json.loads((root / ".audit_board" / "finding_confirmations.json").read_text(encoding="utf-8"))
        if not confirmations.get("findings"):
            raise AssertionError("finding_confirmations.json did not contain findings")

        proof_plans = json.loads((root / ".audit_board" / "proof_plans.json").read_text(encoding="utf-8"))
        if "proof_plans" not in proof_plans:
            raise AssertionError("proof_plans.json missing proof_plans key")

        exploit_hypotheses = (root / ".audit_board" / "exploit_hypotheses.md").read_text(encoding="utf-8")
        if "Structured status:" not in exploit_hypotheses:
            raise AssertionError("exploit_hypotheses.md did not render structured status")

        repair_log = json.loads((root / ".audit_board" / "repair_log.json").read_text(encoding="utf-8"))
        if not isinstance(repair_log.get("events"), list) or not repair_log["events"]:
            raise AssertionError("repair_log.json did not capture preflight events")


def run_nonfoundry_regression_eval() -> None:
    """
    Verify that the skill runs in degraded-but-functional mode
    on a project that has no Foundry (bare solc + git marker only).
    """
    with tempfile.TemporaryDirectory(prefix="cerberus-nonfoundry-") as raw_tmp:
        root = Path(raw_tmp)
        build_bare_solc_fixture(root)

        # Phase: init — should record toolchain_config
        payload = _run_json_command(root, [sys.executable, str(INIT_WORKSPACE), "--target-dir", "src"])
        assert payload.get("ok"), f"init failed in non-Foundry mode: {json.dumps(payload, indent=2)}"
        toolchain = payload.get("details", {}).get("toolchain_config", {})
        assert isinstance(toolchain, dict), "toolchain_config should be a dict"
        assert toolchain.get("preferred_toolchain") != "foundry", "should not prefer foundry without foundry.toml"

        # Phase: architecture — should use concat_imports fallback, not forge flatten
        payload = _run_json_command(root, [sys.executable, str(ANALYZE_ARCHITECTURE), "--target-dir", "src"])
        assert payload.get("ok"), f"architecture failed in non-Foundry mode: {json.dumps(payload, indent=2)}"
        mode = payload.get("mode", "full")
        assert mode in ("degraded", "full"), f"expected degraded or full mode, got: {mode}"
        topology = (root / ".audit_board" / "topology_map.txt").read_text(encoding="utf-8")
        assert "Vault" in topology, f"expected Vault in topology:\n{topology}"

        # Phase: semantic_index — should produce results via regex (no tooling needed)
        payload = _run_json_command(root, [sys.executable, str(SEMANTIC_INDEX), "--target-dir", "src"])
        assert payload.get("ok"), f"semantic_index failed in non-Foundry mode: {json.dumps(payload, indent=2)}"
        semantic = json.loads((root / ".audit_board" / "semantic_index.json").read_text(encoding="utf-8"))
        assert semantic.get("contracts"), "semantic_index should have contracts in non-Foundry mode"

        # Phase: action_catalog — should produce results (no tooling needed)
        payload = _run_json_command(root, [sys.executable, str(EXTRACT_ACTIONS), "--target-dir", "src"])
        assert payload.get("ok"), f"action_catalog failed in non-Foundry mode: {json.dumps(payload, indent=2)}"
        actions = json.loads((root / ".audit_board" / "action_catalog.json").read_text(encoding="utf-8"))
        assert actions.get("actions"), "action_catalog should have actions in non-Foundry mode"

        # Phase: authority_graph — should produce results (no tooling needed)
        payload = _run_json_command(root, [sys.executable, str(AUTHORITY_GRAPH), "--target-dir", "src"])
        assert payload.get("ok"), f"authority_graph failed in non-Foundry mode: {json.dumps(payload, indent=2)}"

        # Phase: state_vectors — should use regex storage inference, not forge inspect
        _mod = load_module("extract_state_vectors_eval", SKILL_RESOURCES / "extract_state_vectors.py")
        # Just verify it doesn't crash; we trust the path is exercised
        payload = _run_json_command(
            root,
            [sys.executable, str(SKILL_RESOURCES / "extract_state_vectors.py"), "--target-dir", "src"],
            expect_ok=False,
        )
        # May or may not be ok depending on slither availability — just check it runs
        assert payload.get("phase") == "state_vectors", f"unexpected phase: {payload.get('phase')}"

        # Phase: finding_candidates — should produce results (no tooling needed)
        for script in (
            DEPENDENCY_GRAPH,
            MINE_INVARIANTS,
            GENERATE_FINDINGS,
        ):
            payload = _run_json_command(root, [sys.executable, str(script), "--target-dir", "src"])
            assert payload.get("ok"), f"{script.name} failed in non-Foundry mode: {json.dumps(payload, indent=2)}"

        findings = json.loads((root / ".audit_board" / "finding_candidates.json").read_text(encoding="utf-8"))
        assert findings.get("findings") is not None, "finding_candidates.json should exist with findings key"


def main() -> int:
    run_architecture_eval()
    run_skip_filter_eval()
    run_quality_gate_eval()
    run_rule_scan_signal_eval()
    run_scaffold_hint_eval()
    run_structured_pipeline_eval()
    run_nonfoundry_regression_eval()
    print("ok: regression evals passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
