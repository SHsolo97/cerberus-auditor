// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

library ECDSA {
    function recover(bytes32 hash, bytes calldata signature) internal pure returns (address) {
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(signature.offset)
            s := calldataload(add(signature.offset, 32))
            v := byte(0, calldataload(add(signature.offset, 64)))
        }
        return ecrecover(hash, v, r, s);
    }
}

/// @notice Authority-drift benchmark: quorum setter is owner-gated but
///         checkpointSubmit (the sink) is unguarded. The auditor should find
///         the guard mismatch. The actual vulnerability (missing sig dedup)
///         is documented in sharp_edges.md for human-driven reasoning.
contract CheckpointValidator {
    address public owner;
    uint256 public quorumThreshold;
    mapping(address => uint256) public validatorWeight;

    constructor() {
        owner = msg.sender;
        quorumThreshold = 51;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // Guarded setter: only owner can change quorum
    function setQuorum(uint256 threshold) external onlyOwner {
        quorumThreshold = threshold;
    }

    // Unguarded sink: checkpoint submission has no auth guard at all.
    // Named "executeCheckpoint" → SINK_HINTS match ("execute") → classified as sink.
    // Generates: authority-drift-setQuorum-executeCheckpoint
    //           + unguarded-sink-executeCheckpoint
    function executeCheckpoint(
        bytes32 hash,
        address[] calldata signatories,
        bytes[] calldata signatures
    ) external returns (bool) {
        uint256 totalWeight;
        for (uint256 i = 0; i < signatories.length; i++) {
            address signer = ECDSA.recover(hash, signatures[i]);
            totalWeight += validatorWeight[signer];
        }
        // Missing sig dedup: same signer counted multiple times
        return totalWeight >= quorumThreshold;
    }

    function setValidatorWeight(address validator, uint256 weight) external onlyOwner {
        validatorWeight[validator] = weight;
    }
}
