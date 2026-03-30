from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, TYPE_CHECKING

from common import AUDIT_DIR, PhaseStatus, finalize, make_failure_status, read_json, write_text, STATUS_FILE, resolve_toolchain, which


# ── Confirmability classification ─────────────────────────────────────────────

# Keywords that indicate a SOFT disqualifier — these do not block
# confirmable_and_reproducible since they represent review recommendations
# rather than structural false-positive signals.
_SOFT_DISQUALIFIER_PATTERNS = (
    "need source review",
    "needs manual",
    "needs follow-up",
    "needs verification",
    "confirm whether",
    "confirm that",
    "verify",
    "review",
    "exact failure",
    "minimal harness",
    "reenter",
    "replay",
)


def _is_structural_disqualifier(text: str) -> bool:
    """Return True if the disqualifier represents a structural FP signal, not a soft review note."""
    lower = text.lower()
    if any(p in lower for p in _SOFT_DISQUALIFIER_PATTERNS):
        return False
    # Explicit structural keywords
    if any(k in lower for k in ("parent guard", "out of scope", "dead code", "no body",
                                 "no implementation", "interface", "setter path",
                                 "scope disqualified", "scope_disqualified")):
        return True
    return False


def _structural_disqualifiers(disqualifiers: List[str]) -> List[str]:
    return [d for d in disqualifiers if _is_structural_disqualifier(d)]


def _classify_confirmability(
    status: str,
    confidence: float,
    disqualifiers: List[str],
    rejection_reason: Optional[str],
    family: str,
    evidence: List[Dict[str, object]],
) -> str:
    """
    Classify the confirmability of a proof plan.

    Labels:
      confirmable_and_reproducible — strong structural signal + concrete path
      confirmable_but_weak          — structural signal present but missing
                                     concrete reproduction path or soft assertions
      interesting_but_unconfirmed  — weak signal or explicitly rejected;
                                     still worth documenting with guidance
    """
    if status == "rejected" or rejection_reason:
        return "interesting_but_unconfirmed"

    structural = _structural_disqualifiers(disqualifiers)
    if confidence >= 0.75 and status == "source_confirmed" and not structural:
        return "confirmable_and_reproducible"

    if status == "source_confirmed" and (confidence >= 0.5 or evidence):
        return "confirmable_but_weak"

    return "interesting_but_unconfirmed"


def _reproducibility_signal(
    status: str,
    confidence: float,
    evidence: List[Dict[str, object]],
    family: str,
) -> str:
    """Return a reproducibility signal classification."""
    if status == "rejected":
        return "low"
    if status == "source_confirmed" and confidence >= 0.75 and evidence:
        return "high"
    if status == "source_confirmed" and (confidence >= 0.5 or evidence):
        return "medium"
    return "low"


def _false_positive_risk(
    disqualifiers: List[str],
    scope_status: str,
    rejection_reason: Optional[str],
    parent_guard: Optional[str],
) -> str:
    """Infer false-positive risk from rejection signals."""
    if rejection_reason:
        return "high"
    if parent_guard:
        return "high"
    if scope_status == "out_of_scope":
        return "medium"
    if any("parent guard" in d.lower() for d in disqualifiers):
        return "high"
    if disqualifiers:
        return "medium"
    return "low"


def _blocking_assumptions(
    family: str,
    disqualifiers: List[str],
    rejection_reason: Optional[str],
    parent_guard: Optional[str],
    scope_status: str,
    guard_analysis: str,
) -> List[str]:
    """List the explicit preconditions that must hold for the PoC to work."""
    assumptions: List[str] = []

    if rejection_reason:
        assumptions.append(f"Rejection reason must be resolved first: {rejection_reason}")
        return assumptions  # already rejected — nothing else matters

    if parent_guard:
        assumptions.append(
            "Child contract must NOT inherit the parent's guard without adding its own."
        )
    if scope_status == "out_of_scope":
        assumptions.append("Target must be confirmed as in-scope for the contest.")
    if guard_analysis and "Needs repo-specific follow-up" in guard_analysis:
        assumptions.append(
            "Guard surface must be verified against actual source — automated analysis inconclusive."
        )

    if family == "authority_drift":
        assumptions.append("Setter must be callable without the sink's guard.")
        assumptions.append("Setter must be reachable by the attacker actor.")
        if any("setter" in d.lower() for d in disqualifiers):
            assumptions.append("Setter guard mismatch must be confirmed as exploitable.")
    elif family == "callback_state_drift":
        assumptions.append("External contract must be controllable by the attacker.")
        assumptions.append("Callback must be reachable before the victim's state is settled.")
    elif family == "broken_recovery":
        assumptions.append("Recovery action must be reachable after the frozen/locked state.")
        assumptions.append("Recovery must not be guarded by the same role that can cause the break.")
    elif family == "implementation_rebinding":
        assumptions.append(
            "Rebinding must be reachable through an admin path that does not guard the sink."
        )
        assumptions.append("The rebound implementation must be deployed or deployable.")
    elif family == "dependency_recovery_lockup":
        assumptions.append("Dependency must be injectable or replaceable by the attacker.")
    elif family == "settlement_dependency_drift":
        assumptions.append("Settlement must read from the drifted dependency value.")
        assumptions.append("Attacker must be able to influence the dependency before settlement.")

    for d in disqualifiers:
        if "setter" in d.lower():
            assumptions.append(f"Setter concern to resolve: {d}")
        elif "guard" in d.lower() and "parent" not in d.lower():
            assumptions.append(f"Guard concern to resolve: {d}")

    return assumptions


def _minimum_test_commands(
    family: str,
    finding_id: str,
    sink_function: str,
    title: str,
    toolchain: str = "foundry",
) -> List[str]:
    """
    Concrete test commands that would exercise this finding.

    Parameterized by toolchain:
    - foundry: forge test / forge script
    - hardhat: npx hardhat test / npx hardhat run
    - generic: toolchain-agnostic comment
    """
    cmds: List[str] = []

    if toolchain == "foundry":
        if family == "authority_drift":
            cmds.extend([
                (
                    f"forge test --match-contract {finding_id.replace('-', '_').replace('_', '')} "
                    f"--match-test testUnauthorized{sink_function.title().replace('_', '')} -vvv"
                ),
                (
                    "forge script script/Exploit.s.sol --fork-url <RPC_URL> "
                    "--sender <ATTACKER_ADDR> --sig run() -vvv"
                ),
            ])
        elif family == "callback_state_drift":
            cmds.extend([
                (
                    "forge test --match-test testCallbackManipulatesState -vvvv "
                    "--fork-url <RPC_URL>"
                ),
            ])
        elif family == "broken_recovery":
            cmds.extend([
                (
                    "forge test --match-test testRecoveryUnreachableAfterFreeze -vvvv "
                    "--fork-url <RPC_URL>"
                ),
            ])
        elif family == "implementation_rebinding":
            cmds.extend([
                (
                    "forge test --match-test testImplRebindUnauthorized -vvvv "
                    "--fork-url <RPC_URL>"
                ),
            ])
        elif family in ("dependency_recovery_lockup", "settlement_dependency_drift"):
            cmds.extend([
                (
                    f"forge script script/{finding_id.title().replace('-', '')}.s.sol "
                    "--fork-url <RPC_URL> --sig run() -vvv"
                ),
            ])
        # Always add a fuzz-invariant check
        cmds.append(
            "forge test --match-invariant invariant_authority_preserved -vvv "
            "--fork-url <RPC_URL>"
        )

    elif toolchain == "hardhat":
        if family == "authority_drift":
            cmds.extend([
                f"npx hardhat test --grep \"Unauthorized{sink_function.title().replace('_', '')}\" -vvv",
                "npx hardhat run scripts/Exploit.ts --network localhost",
            ])
        elif family == "callback_state_drift":
            cmds.extend([
                "npx hardhat test --grep \"Callback\" -vvvv",
            ])
        elif family == "broken_recovery":
            cmds.extend([
                "npx hardhat test --grep \"Recovery\" -vvvv",
            ])
        elif family == "implementation_rebinding":
            cmds.extend([
                "npx hardhat test --grep \"Rebind\" -vvvv",
            ])
        elif family in ("dependency_recovery_lockup", "settlement_dependency_drift"):
            cmds.extend([
                "npx hardhat run scripts/Exploit.ts --network localhost",
            ])
        cmds.append("npx hardhat test --grep \"invariant\" -vvv")

    else:
        # generic — emit toolchain-agnostic guidance
        cmds.extend([
            f"# Implement test for {family} finding: {finding_id}",
            "# Suggested: assert violation of invariant after calling " + sink_function,
            "# Recommended: migrate to foundry or hardhat for a richer test harness.",
        ])

    return cmds[:4]


# ── Argument parsing ─────────────────────────────────────────────────────────

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Plan deterministic proofs for confirmed findings.")
    parser.add_argument("--target-dir", required=True)
    return parser.parse_args()


def gather_test_candidates() -> List[str]:
    test_root = Path("test")
    if not test_root.exists():
        return []
    return sorted(str(path) for path in test_root.rglob("*.sol"))[:12]


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    args = parse_args()
    artifacts = {"proof_plans": str(AUDIT_DIR / "proof_plans.json")}
    confirmations = read_json(AUDIT_DIR / "finding_confirmations.json")
    candidate_map: Dict[str, Dict[str, object]] = {
        str(item.get("id", "")): item
        for item in read_json(AUDIT_DIR / "finding_candidates.json").get("findings", [])
        if isinstance(item, dict)
    }
    findings = confirmations.get("findings") if isinstance(confirmations, dict) else None
    if not isinstance(findings, list):
        return finalize(
            make_failure_status(
                "proof_planning",
                errors=["finding_confirmations.json is missing or invalid."],
                artifacts=artifacts,
            )
        )

    test_candidates = gather_test_candidates()
    proof_plans: List[Dict[str, object]] = []

    # Detect preferred toolchain from init phase
    preferred_toolchain = "foundry"
    status_snapshot = read_json(STATUS_FILE)
    init_details = status_snapshot.get("init", {}).get("details", {}) if isinstance(status_snapshot, dict) else {}
    toolchain_config = init_details.get("toolchain_config") or {}
    if isinstance(toolchain_config, dict):
        preferred = toolchain_config.get("preferred_toolchain", "foundry")
        if preferred and preferred != "unknown":
            preferred_toolchain = str(preferred)
    else:
        # Fallback: resolve from filesystem
        tc = resolve_toolchain(Path(".").resolve())
        preferred_toolchain = tc.preferred_toolchain

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        # Include all statuses so interesting-but-unconfirmed findings are still documented
        status = str(finding.get("status", ""))
        candidate_id = str(finding.get("candidate_id", ""))
        candidate = candidate_map.get(candidate_id, {})
        family = str(candidate.get("family", ""))

        # Include all families with structured guidance in proof planning
        known_families = {
            "authority_drift",
            "callback_state_drift",
            "broken_recovery",
            "implementation_rebinding",
            "dependency_recovery_lockup",
            "settlement_dependency_drift",
            "arithmetic_bugs",
            "cross_chain_accounting",
            "ipc_message_handling",
        }

        # Build the rich confirmation context
        confidence = float(finding.get("confidence_score", 0.5))
        disqualifiers: List[str] = list(finding.get("disqualifiers", []))
        rejection_reason: Optional[str] = (
            str(finding.get("rejection_reason", "")).strip() or None
        )
        scope_status = str(finding.get("scope_status", "unknown"))
        guard_analysis = str(finding.get("guard_analysis", ""))
        evidence: List[Dict[str, object]] = (
            list(candidate.get("evidence", [])) if isinstance(candidate.get("evidence"), list) else []
        )

        # Re-read authority graph for parent-guard check if needed
        authority_graph = read_json(AUDIT_DIR / "authority_graph.json")
        sinks = authority_graph.get("sinks", []) if isinstance(authority_graph, dict) else []
        parent_guard_reason: Optional[str] = None
        if family in {"authority_drift", "callback_state_drift"}:
            target_list = (
                list(finding.get("target_functions", []))
                if isinstance(finding.get("target_functions"), list)
                else []
            )
            target_contract = str(finding.get("target_contract", "")).strip()
            if target_list and target_contract:
                meta = _build_semantic_metadata()
                parent_guard_reason = _parent_guard_status(
                    target_list, target_contract, meta, sinks,
                )

        confirmability = _classify_confirmability(
            status, confidence, disqualifiers, rejection_reason, family, evidence,
        )
        repro_signal = _reproducibility_signal(status, confidence, evidence, family)
        fp_risk = _false_positive_risk(disqualifiers, scope_status, rejection_reason, parent_guard_reason)
        assumptions = _blocking_assumptions(
            family, disqualifiers, rejection_reason, parent_guard_reason,
            scope_status, guard_analysis,
        )
        min_cmds = _minimum_test_commands(
            family, candidate_id, str(finding.get("sink_function", "")), str(finding.get("title", "")),
            toolchain=preferred_toolchain,
        )

        sink_function = str(finding.get("sink_function", "target function"))

        # Include all families with known templates AND all confirmable candidates
        # (Item 13: source_confirmed and confirmable_and_reproducible qualify regardless of family)
        if family in known_families or confirmability in ("confirmable_and_reproducible", "confirmable_but_weak"):
            proof_plans.append({
                # ── Identification ───────────────────────────────────────────────
                "finding_id": candidate_id,
                "title": str(finding.get("title", "")),
                "family": family,
                "status": status,
                # ── Confirmability scoring ─────────────────────────────────────────
                "confirmability": confirmability,
                "reproducibility_signal": repro_signal,
                "false_positive_risk": fp_risk,
                # ── Confidence ───────────────────────────────────────────────────
                "confidence_score": confidence,
                "confidence_boost": float(finding.get("confidence_boost", 0.0)),
                # ── Rejection context ────────────────────────────────────────────
                "rejection_reason": rejection_reason,
                "scope_status": scope_status,
                "guard_analysis": guard_analysis,
                # ── What must be true ─────────────────────────────────────────────
                "blocking_assumptions": assumptions,
                # ── Proof scaffolding ─────────────────────────────────────────────
                "harness_candidates": test_candidates[:5],
                "required_actors": _required_actors(family),
                "setup_requirements": _setup_requirements(family, status),
                "transaction_sequence": _transaction_sequence(family, sink_function, status),
                "assertions": _assertions(family, status, finding),
                "expected_outcome": _expected_outcome(confirmability, status),
                "preferred_test_path": test_candidates[0] if test_candidates else "test/root-audit",
                # ── Concrete commands ─────────────────────────────────────────────
                "minimum_test_commands": min_cmds,
                "preferred_toolchain": preferred_toolchain,
            })

    write_text(
        Path(artifacts["proof_plans"]),
        json.dumps({"proof_plans": proof_plans}, indent=2, sort_keys=True) + "\n",
    )
    status_obj = PhaseStatus(
        phase="proof_planning",
        ok=True,
        mode="full",
        artifacts=artifacts,
        warnings=[],
        errors=[],
        details={
            "target_dir": args.target_dir,
            "proof_plan_count": len(proof_plans),
            "confirmability_breakdown": {
                "confirmable_and_reproducible": sum(
                    1 for p in proof_plans if p.get("confirmability") == "confirmable_and_reproducible"
                ),
                "confirmable_but_weak": sum(
                    1 for p in proof_plans if p.get("confirmability") == "confirmable_but_weak"
                ),
                "interesting_but_unconfirmed": sum(
                    1 for p in proof_plans if p.get("confirmability") == "interesting_but_unconfirmed"
                ),
            },
        },
    )
    return finalize(status_obj)


# ── Helpers for proof plan enrichment ────────────────────────────────────────

def _required_actors(family: str) -> List[str]:
    if family in {"authority_drift", "implementation_rebinding"}:
        return ["attacker", "privileged_actor", "regular_user"]
    if family in {"callback_state_drift", "dependency_recovery_lockup", "settlement_dependency_drift"}:
        return ["attacker", "external_contract", "regular_user"]
    if family == "broken_recovery":
        return ["attacker", "admin", "regular_user"]
    return ["attacker", "regular_user"]


def _setup_requirements(family: str, status: str) -> List[str]:
    base = ["Reach the minimal vulnerable state using the existing repo harness where possible."]
    if status == "rejected":
        return [
            "This finding was rejected — document why the rejection applies here.",
            "Resolve the rejection reason before proceeding.",
        ]
    if status == "weak_signal":
        base.append(
            "Weak signal: manually verify the exploit path exists in source before proceeding."
        )
    if family == "authority_drift":
        base.append("Deploy the setter-controllable state to a value the sink will read.")
    elif family == "callback_state_drift":
        base.append("Deploy a mock attacker contract that calls back into the target.")
    elif family == "broken_recovery":
        base.append("Trigger the frozen/locked state first, then attempt recovery.")
    elif family == "implementation_rebinding":
        base.append("Deploy a malicious implementation contract.")
    elif family == "dependency_recovery_lockup":
        base.append("Replace the dependency with a halted or griefing version.")
    elif family == "settlement_dependency_drift":
        base.append("Front-run the settlement oracle with a manipulated value.")
    return base


def _transaction_sequence(family: str, sink_function: str, status: str) -> List[str]:
    if status == "rejected":
        return ["N/A — finding was rejected. Document the rejection reason and skip."]

    seq = [f"Call {sink_function} under the precise state assumptions."]

    if family == "authority_drift":
        seq.insert(0, "Call the unguarded setter to drift the shared state.")
        seq.append(
            "Call the sink — observe that it accepts the drifted value without the expected guard.",
        )
    elif family == "callback_state_drift":
        seq.insert(0, "Attacker contract calls back into the target during its own transaction.")
        seq.append("Observe that target state changed unexpectedly before settlement.")
    elif family == "broken_recovery":
        seq.insert(0, "Trigger the freeze condition.")
        seq.append("Call the recovery action — observe revert or ineffective state change.")
    elif family == "implementation_rebinding":
        seq.insert(0, "Call the admin setter to bind the implementation to a malicious contract.")
        seq.append(f"Call {sink_function} — observe behavior controlled by the malicious impl.")
    elif family in {"dependency_recovery_lockup", "settlement_dependency_drift"}:
        seq.insert(0, "Inject the manipulated dependency value.")
        seq.append("Call the dependent action — observe incorrect settlement or lockup.")

    seq.append("Observe revert, unauthorized reachability, or measurable invariant break.")
    return seq


def _assertions(family: str, status: str, finding: Dict[str, object]) -> List[str]:
    if status == "rejected":
        return ["N/A — finding was rejected."]
    state_arg = str(finding.get("state_argument", "Demonstrate a concrete invariant violation."))
    base = [state_arg]
    if family == "authority_drift":
        base.append("assertEq(sink_result, expected_result, 'authority-gate bypassed')")
    elif family == "callback_state_drift":
        base.append("assertTrue(target.stateMatchesExpected(), 'callback corrupted state')")
    elif family == "broken_recovery":
        base.append("assertFalse(recoverySucceeded, 'recovery action should fail')")
    elif family == "implementation_rebinding":
        base.append("assertEq(impl.owner(), attacker, 'malicious impl installed')")
    elif family in {"dependency_recovery_lockup", "settlement_dependency_drift"}:
        base.append("assertEq(settlement.value(), expectedValue, 'drifted dependency used')")
    return base


def _expected_outcome(confirmability: str, status: str) -> str:
    if status == "rejected":
        return "rejected"
    if confirmability == "confirmable_and_reproducible":
        return "deterministic_poc_candidate"
    if confirmability == "confirmable_but_weak":
        return "hypothesis_needs_manual_proof"
    return "interesting_but_unconfirmed"


# ── Semantic metadata helpers (mirrored from confirm_findings.py) ─────────────

def _build_semantic_metadata() -> Dict[str, Any]:
    meta: Dict[str, Any] = {
        "contract_inherits": {},
        "contract_to_file": {},
        "contract_kind": {},
    }
    for index_name in ("ast_semantic_index", "semantic_index"):
        idx_path = AUDIT_DIR / f"{index_name}.json"
        if not idx_path.exists():
            continue
        data = read_json(idx_path)
        if not isinstance(data, dict):
            continue
        contracts = data.get("contracts", [])
        if not isinstance(contracts, list):
            contracts = []
        for centry in contracts:
            if not isinstance(centry, dict):
                continue
            cname = str(centry.get("name", "")).strip()
            if not cname:
                continue
            meta["contract_kind"][cname] = str(centry.get("kind", "contract")).lower()
            meta["contract_inherits"][cname] = list(centry.get("inherits", []))
            meta["contract_to_file"][cname] = str(centry.get("path", ""))
        if meta["contract_to_file"]:
            break
    return meta


def _parent_guard_status(
    target_functions: List[str],
    target_contract: str,
    meta: Dict[str, Any],
    authority_sinks: List[Dict[str, object]],
) -> Optional[str]:
    inherits = list(meta.get("contract_inherits", {}).get(target_contract, []))
    if not inherits:
        return None
    for parent in inherits:
        for sink_entry in authority_sinks:
            if not isinstance(sink_entry, dict):
                continue
            sink_fn = str(sink_entry.get("function", ""))
            sink_c = str(sink_entry.get("contract", ""))
            guards = sink_entry.get("guards") or sink_entry.get("require_guards") or sink_entry.get("auth_guards", [])
            if sink_fn in target_functions and sink_c == parent and guards:
                return (
                    f"Function '{sink_fn}' is guarded in parent contract '{parent}'; "
                    f"child '{target_contract}' inherits the guard."
                )
    return None


if __name__ == "__main__":
    raise SystemExit(main())
