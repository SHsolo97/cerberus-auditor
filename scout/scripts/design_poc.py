from __future__ import annotations

import argparse
import re
from pathlib import Path  # noqa: F401 — used in _has_hardhat_config
from typing import Dict, List, Sequence, Tuple

from common import (
    AUDIT_DIR,
    STATUS_FILE,
    PhaseStatus,
    finalize,
    make_failure_status,
    read_json,
    read_text_file,
    strip_solidity_comments,
    write_text,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Design a deterministic PoC and submission framing.")
    parser.add_argument("--finding-title", help="Human-readable finding title.")
    parser.add_argument("--finding-id", help="Structured finding id from proof_plans.json or finding_confirmations.json.")
    parser.add_argument("--target-contract-name", help="Preferred target contract name.")
    parser.add_argument("--target-contract-path", help="Repo-relative path to the primary contract.")
    return parser.parse_args()


def keyword_set(*parts: str) -> List[str]:
    joined = " ".join(part for part in parts if part)
    tokens = re.findall(r"[a-zA-Z][a-zA-Z0-9_]{2,}", joined.lower())
    return sorted(set(tokens))


def score_text_against_keywords(text: str, path: Path, keywords: Sequence[str]) -> int:
    lowered = text.lower()
    path_lowered = path.as_posix().lower()
    score = 0
    for keyword in keywords:
        if keyword in path_lowered:
            score += 3
        occurrences = lowered.count(keyword)
        score += min(occurrences, 4)
    if "fixture" in path_lowered or "fixtures" in path_lowered:
        score += 2
    if "mock" in path_lowered:
        score += 1
    return score


def gather_test_candidates(target_contract_name: str | None, target_contract_path: str | None, title: str) -> List[Tuple[str, int]]:
    scores: List[Tuple[str, int]] = []
    test_root = Path("test")
    if not test_root.exists():
        return scores
    keywords = keyword_set(title, target_contract_name or "", Path(target_contract_path).stem if target_contract_path else "")

    for extension in ("*.ts", "*.sol"):
        for path in test_root.rglob(extension):
            content = read_text_file(path)
            if not content:
                continue
            score = score_text_against_keywords(content, path, keywords)
            if target_contract_name and target_contract_name.lower() in content.lower():
                score += 4
            if score:
                scores.append((str(path), score))
    scores.sort(key=lambda item: (-item[1], item[0]))
    return scores[:10]


def gather_mock_candidates(target_contract_name: str | None, title: str) -> List[Tuple[str, int]]:
    contracts_root = Path("contracts")
    if not contracts_root.exists():
        return []
    keywords = keyword_set(title, target_contract_name or "")
    matches: List[Tuple[str, int]] = []
    for path in contracts_root.rglob("*.sol"):
        lowered_path = path.as_posix().lower()
        if "mock" not in lowered_path and "test" not in lowered_path:
            continue
        content = read_text_file(path)
        if not content:
            continue
        score = score_text_against_keywords(content, path, keywords)
        if "mock" in lowered_path:
            score += 2
        if score:
            matches.append((str(path), score))
    matches.sort(key=lambda item: (-item[1], item[0]))
    return matches[:8]


def gather_fixture_candidates(target_contract_name: str | None, title: str) -> List[Tuple[str, int]]:
    keywords = keyword_set(title, target_contract_name or "")
    matches: List[Tuple[str, int]] = []
    for root_name in ("test", "scripts"):
        root = Path(root_name)
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            lowered = path.as_posix().lower()
            if "fixture" not in lowered and "base" not in lowered and "helper" not in lowered:
                continue
            content = read_text_file(path)
            if not content:
                continue
            score = score_text_against_keywords(content, path, keywords)
            if score:
                matches.append((str(path), score))
    matches.sort(key=lambda item: (-item[1], item[0]))
    return matches[:6]


def extract_function_names(path_str: str | None) -> List[str]:
    if not path_str:
        return []
    path = Path(path_str)
    content = strip_solidity_comments(read_text_file(path))
    if not content:
        return []
    return re.findall(r"\bfunction\s+([A-Za-z_][A-Za-z0-9_]*)\s*\(", content)


def classify_finding(title: str) -> Dict[str, object]:
    lowered = title.lower()
    if any(token in lowered for token in ("lockup", "stuck", "stranded", "unsettled", "permanent", "asset")):
        return {
            "severity": "High",
            "likelihood": "Medium",
            "impact": "High",
            "template": "minimal_with_poc",
            "family": "asset_lockup",
            "broken_invariant": "Once expiry is reached, the protocol should retain a deterministic recovery path.",
            "assertions": [
                "reach the vulnerable state with the minimal existing fixture",
                "show the protocol reports or implies recoverability",
                "show the concrete recovery or settlement call still reverts",
                "show the affected assets remain stranded or control cannot be regained",
            ],
            "report_focus": "Emphasize the mismatch between apparent recoverability and actual failed recovery.",
        }
    if any(token in lowered for token in ("rotation", "governance", "registry", "recovery")):
        return {
            "severity": "Low",
            "likelihood": "High",
            "impact": "Low",
            "template": "detailed_with_instructions",
            "family": "governance_recovery",
            "broken_invariant": "Governance should be able to rotate security-relevant dependencies during incident response.",
            "assertions": [
                "set the dependency once through the normal privileged path",
                "show toggling still works if relevant",
                "attempt a legitimate rotation to a new dependency address",
                "show the protocol permanently rejects the rotation",
            ],
            "report_focus": "Frame it as a real recovery-path weakness and blast-radius amplifier, not direct fund loss.",
        }
    if any(token in lowered for token in ("allowance", "approval", "stale", "revoke")):
        return {
            "severity": "Medium",
            "likelihood": "Medium",
            "impact": "Medium",
            "template": "minimal_with_poc",
            "family": "stale_approval",
            "broken_invariant": "Temporary authority should be revoked during cleanup.",
            "assertions": [
                "grant the transient approval or authority through the intended path",
                "trigger the cleanup or replacement flow",
                "show the stale approval or authority remains usable afterward",
                "show the stale actor can still reach a meaningful token pull or privileged sink",
            ],
            "report_focus": "Show the stale capability survives the exact state transition that should have revoked it.",
        }
    return {
        "severity": "Not determined",
        "likelihood": "Not determined",
        "impact": "Not determined",
        "template": "severity_argument_only",
        "family": "generic",
        "broken_invariant": "Not determined",
        "assertions": [
            "identify the smallest reproducible fixture",
            "reach the suspicious state transition",
            "measure the actual failure or unauthorized capability",
        ],
        "report_focus": "Determine severity from contest-specific impact and exploitability.",
    }


def guess_run_command(test_candidates: Sequence[Tuple[str, int]], template: str) -> str:
    if not test_candidates:
        return "Prefer a focused command that runs only the final PoC file."
    best_path = test_candidates[0][0]

    # Load preferred_toolchain from the toolchain config written by cerberus-profiler.
    preferred = None
    config_path = AUDIT_DIR / "toolchain_config.json"
    if config_path.exists():
        cfg = read_json(config_path)
        if isinstance(cfg, dict):
            preferred = str(cfg.get("preferred_toolchain", "")).lower()

    # Route by toolchain; fall back to extension-based inference.
    if preferred in ("foundry", "bare"):
        from common import which
        forge_bin = which("forge")
        if forge_bin and best_path.endswith(".sol"):
            return f"forge test --match-path {best_path}"
        if forge_bin and best_path.endswith((".ts", ".js")):
            return f"{forge_bin} test {best_path}  # foundry; adapt if this is a Hardhat fixture"
        solc_bin = which("solc")
        if solc_bin:
            return f"solc --bin-runtime {best_path}  # compile only; implement test in your framework"
        return "# No Solidity toolchain detected; implement test manually"

    if preferred in ("hardhat", "truffle"):
        suffix = " --network hardhat" if best_path.endswith(".sol") else ""
        if best_path.endswith((".ts", ".js")):
            return f"npx hardhat test {best_path}{suffix}"
        # .sol file in a Hardhat project: run via Hardhat's compile + script
        if best_path.endswith(".sol"):
            return f"npx hardhat compile && npx hardhat run scripts/test_poc.js  # adapt script path for {best_path}"
        return f"npx hardhat test  # adapt for {best_path}"

    if preferred == "brownie":
        if best_path.endswith(".py"):
            return f"brownie test {best_path}"
        if best_path.endswith(".sol"):
            return f"brownie test tests/test_{Path(best_path).stem}.py  # create brownie test importing {best_path}"
        return f"brownie test  # adapt for {best_path}"

    if preferred == "anchor":
        if best_path.endswith((".ts", ".js")):
            return f"anchor test {best_path}"
        if best_path.endswith(".sol"):
            return f"# Anchor project: write TS test that calls {best_path} via CPI or anchor test"
        return f"anchor test  # adapt for {best_path}"

    # No preferred_toolchain in config — infer from file extension.
    if best_path.endswith(".ts"):
        if _has_hardhat_config():
            return f"npx hardhat test {best_path}"
        return f"# .ts file: configure Hardhat, Truffle, or Anchor, then run tests"
    if best_path.endswith(".js"):
        if _has_hardhat_config():
            return f"npx hardhat test {best_path}"
        return f"# .js file: configure Hardhat or Truffle, then run tests"
    if best_path.endswith(".py"):
        if _has_brownie_config():
            return f"brownie test {best_path}"
        return f"# .py file: Brownie project required; install brownie and run tests"
    if best_path.endswith(".sol"):
        from common import which
        forge_bin = which("forge")
        if forge_bin:
            return f"forge test --match-path {best_path}"
        solc_bin = which("solc")
        if solc_bin:
            return f"solc --bin-runtime {best_path}  # compile only; implement test in your framework"
        return "# No Solidity test framework detected; implement test manually"
    return f"# No recognized framework for {best_path}; implement test manually"


def _has_hardhat_config() -> bool:
    """Check if the project has a Hardhat config file."""
    for name in ("hardhat.config.ts", "hardhat.config.js"):
        if Path(name).exists():
            return True
    return False


def _has_brownie_config() -> bool:
    """Check if the project has a Brownie config file."""
    for name in ("brownie-config.yaml", "brownie-config.yml"):
        if Path(name).exists():
            return True
    return False


def structured_finding_context(finding_id: str) -> Dict[str, object]:
    proof_plans_data = read_json(AUDIT_DIR / "proof_plans.json")
    confirmations_data = read_json(AUDIT_DIR / "finding_confirmations.json")
    proof_plans = proof_plans_data.get("proof_plans") if isinstance(proof_plans_data, dict) else None
    confirmations = confirmations_data.get("findings") if isinstance(confirmations_data, dict) else None
    if not isinstance(proof_plans, list):
        proof_plans = []
    if not isinstance(confirmations, list):
        confirmations = []

    proof_plan = next((item for item in proof_plans if isinstance(item, dict) and item.get("finding_id") == finding_id), {})
    confirmation = next((item for item in confirmations if isinstance(item, dict) and item.get("candidate_id") == finding_id), {})
    title = str(proof_plan.get("title") or confirmation.get("title") or finding_id)
    target_path = ""
    source_paths = confirmation.get("source_paths")
    if isinstance(source_paths, list) and source_paths:
        target_path = str(source_paths[0])
    sink_function = str(confirmation.get("sink_function", ""))
    assertions = proof_plan.get("assertions") if isinstance(proof_plan, dict) else None
    if not isinstance(assertions, list):
        assertions = []
    return {
        "title": title,
        "target_contract_path": target_path or None,
        "target_contract_name": sink_function if sink_function not in {"", "not_determined"} else None,
        "assertions": assertions,
        "proof_plan": proof_plan,
        "confirmation": confirmation,
    }


def render_poc_spec(
    title: str,
    target_contract_name: str | None,
    target_contract_path: str | None,
    classification: Dict[str, object],
    test_candidates: Sequence[Tuple[str, int]],
    fixture_candidates: Sequence[Tuple[str, int]],
    mock_candidates: Sequence[Tuple[str, int]],
    functions: Sequence[str],
) -> str:
    lines = ["# PoC Spec", "", "## Finding", f"- Title: {title}"]
    lines.append(f"- Target contract: {target_contract_name or 'Not determined'}")
    lines.append(f"- Target path: {target_contract_path or 'Not determined'}")
    lines.append(f"- Broken invariant: {classification['broken_invariant']}")
    lines.append(f"- Exploit family: {classification['family']}")
    lines.append("")
    lines.append("## Recommended Harness")
    if test_candidates:
        for path, score in test_candidates[:5]:
            lines.append(f"- Candidate test file: {path} (match score {score})")
    else:
        lines.append("- Candidate test file: Not determined")
    if fixture_candidates:
        for path, score in fixture_candidates[:4]:
            lines.append(f"- Candidate fixture/helper: {path} (match score {score})")
    else:
        lines.append("- Candidate fixture/helper: Not determined")
    if mock_candidates:
        for path, score in mock_candidates[:5]:
            lines.append(f"- Candidate mock/helper: {path} (match score {score})")
    else:
        lines.append("- Candidate mock/helper: Not determined")
    lines.append("")
    lines.append("## Minimal Deterministic Assertions")
    for assertion in classification["assertions"]:
        lines.append(f"- {assertion}")
    lines.append("")
    lines.append("## Candidate Functions")
    if functions:
        for name in functions[:12]:
            lines.append(f"- {name}")
    else:
        lines.append("- Not determined")
    lines.append("")
    lines.append("## Suggested Run Command")
    lines.append(f"- {guess_run_command(test_candidates, str(classification['template']))}")
    return "\n".join(lines).rstrip() + "\n"


def render_severity_assessment(title: str, classification: Dict[str, object]) -> str:
    lines = [
        "# Severity Assessment",
        "",
        f"- Proposed severity: {classification['severity']}",
        f"- Likelihood: {classification['likelihood']}",
        f"- Impact: {classification['impact']}",
        f"- Broken invariant: {classification['broken_invariant']}",
    ]
    family = str(classification["family"])
    if family == "asset_lockup":
        lines.append("- Rationale: this pattern points to protocol-owned asset lockup or irreversible liveness failure after a supposedly recoverable state.")
    elif family == "governance_recovery":
        lines.append("- Rationale: this pattern weakens incident response and safe migration, but does not directly cause asset loss by itself.")
        lines.append("- Framing note: present it as a standalone recovery-path weakness and as an amplifier for other findings.")
    elif family == "stale_approval":
        lines.append("- Rationale: stale authority bugs are severity-sensitive; scoring depends on whether the surviving capability can still move funds or reach a privileged sink.")
    else:
        lines.append("- Rationale: contest-specific manual scoring still required.")
    lines.append(f"- Reporting focus: {classification['report_focus']}")
    return "\n".join(lines).rstrip() + "\n"


def render_submission_notes(title: str, classification: Dict[str, object]) -> str:
    template = str(classification["template"])
    lines = [
        "# Submission Notes",
        "",
        f"- Recommended template: {template}",
        f"- Title: {title}",
        "- Lead with the broken invariant rather than the implementation detail.",
        "- State the measurable impact before the root-cause discussion.",
        "- Keep the PoC minimal, deterministic, and scoped to the protocol-owned impact.",
        "- Prefer short reproduction steps that map directly to the final assertions.",
    ]
    if template == "minimal_with_poc":
        lines.append("- Use 2-4 short paragraphs for description, then a compact PoC section and a narrow recommendation.")
    elif template == "detailed_with_instructions":
        lines.append("- Explicitly explain why the issue is valid even if severity-capped, then give exact reproduction steps.")
    else:
        lines.append("- Center the report on severity rationale and why the issue should still be accepted.")
    lines.append(f"- Report emphasis: {classification['report_focus']}")
    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    args = parse_args()
    status_snapshot = read_json(STATUS_FILE)
    init_details = status_snapshot.get("init", {}).get("details", {}) if isinstance(status_snapshot, dict) else {}
    run_id = init_details.get("run_id")

    title = args.finding_title or ""
    target_contract_name = args.target_contract_name
    target_contract_path = args.target_contract_path
    forced_assertions: List[str] = []

    if args.finding_id:
        context = structured_finding_context(args.finding_id)
        title = title or str(context["title"])
        target_contract_name = target_contract_name or context["target_contract_name"]
        target_contract_path = target_contract_path or context["target_contract_path"]
        forced_assertions = list(context.get("assertions", []))

    if not title.strip():
        status = make_failure_status("poc_design", errors=["Finding title or finding id must not be empty."], details={"run_id": run_id})
        return finalize(status)

    classification = classify_finding(title)
    if forced_assertions:
        classification = {**classification, "assertions": forced_assertions}
    test_candidates = gather_test_candidates(target_contract_name, target_contract_path, title)
    fixture_candidates = gather_fixture_candidates(target_contract_name, title)
    mock_candidates = gather_mock_candidates(target_contract_name, title)
    functions = extract_function_names(target_contract_path)

    write_text(
        AUDIT_DIR / "poc_spec.md",
        render_poc_spec(
            title,
            target_contract_name,
            target_contract_path,
            classification,
            test_candidates,
            fixture_candidates,
            mock_candidates,
            functions,
        ),
    )
    write_text(
        AUDIT_DIR / "severity_assessment.md",
        render_severity_assessment(title, classification),
    )
    write_text(AUDIT_DIR / "submission_notes.md", render_submission_notes(title, classification))

    status = PhaseStatus(
        phase="poc_design",
        ok=True,
        mode="full",
        artifacts={
            "poc_spec": str(AUDIT_DIR / "poc_spec.md"),
            "severity_assessment": str(AUDIT_DIR / "severity_assessment.md"),
            "submission_notes": str(AUDIT_DIR / "submission_notes.md"),
        },
        warnings=[],
        errors=[],
        details={
            "finding_title": title,
            "finding_id": args.finding_id,
            "target_contract_name": target_contract_name,
            "target_contract_path": target_contract_path,
            "run_id": run_id,
            "severity": classification["severity"],
            "template": classification["template"],
            "test_candidates": [path for path, _ in test_candidates[:5]],
            "fixture_candidates": [path for path, _ in fixture_candidates[:4]],
            "mock_candidates": [path for path, _ in mock_candidates[:5]],
        },
    )
    return finalize(status)


if __name__ == "__main__":
    raise SystemExit(main())
