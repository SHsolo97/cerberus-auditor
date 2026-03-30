// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

enum IpcMsgKind { Transfer, Call, Result }

struct IpcEnvelope {
    IpcMsgKind kind;
    uint256 value;
    address to;
    address from;
    uint256 localNonce;
}

/// @notice Authority-drift benchmark: adminSetCircSupply is owner-gated,
///         but execBottomUpMsgs (the supply-modifying sink) is unguarded.
///         The guard mismatch generates an authority-drift finding.
///         The semantic bug (Call-kind bypassing circSupply) is documented
///         in sharp_edges.md for human-driven reasoning.
contract SubnetGateway {
    address public owner;
    uint256 public circSupply;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // Guarded setter: only owner can set circSupply directly
    // Named "configure*" to be setter-like (is_setter_like: "configure" prefix)
    function configureCircSupply(uint256 supply) external onlyOwner {
        circSupply = supply;
    }

    // Unguarded sink: writes to circSupply but has no guard.
    // Named "execute*" to trigger SINK_HINTS ("execute") → becomes a sink in authority graph.
    // Guard mismatch with adminSetCircSupply triggers authority-drift finding.
    // Semantic bug: Call-kind messages with value are excluded from totalValue,
    // bypassing circSupply accounting (see sharp_edges.md).
    function executeBottomUpMsgs(IpcEnvelope[] calldata msgs) external {
        uint256 totalValue;
        for (uint256 i = 0; i < msgs.length; i++) {
            // Only non-Call messages contribute to totalValue.
            // Call-kind messages with value > 0 are silently skipped.
            if (msgs[i].kind != IpcMsgKind.Call) {
                totalValue += msgs[i].value;
            }
        }
        require(circSupply >= totalValue, "Insufficient circ supply");
        circSupply -= totalValue;
    }
}
