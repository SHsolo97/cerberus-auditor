// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

enum IpcMsgKind { Transfer, Call, Result }

struct IpcEnvelope {
    IpcMsgKind kind;
    address to;
    address from;
    uint256 value;
    bytes message;
    uint256 localNonce;
    uint256 originalNonce;
}

/// @notice Authority-drift benchmark for IPC hash mismatch.
///         The semantic bug (toHash/toTracingId nonce mismatch) causes
///         result receipts to never match in-flight messages, locking
///         funds in inflightMsgs. Documented in sharp_edges.md.
///         The structural pattern: guarded setter configureResultHandler
///         vs unguarded sink executeResult. Both write to handler slot,
///         generating authority-drift and unguarded-sink findings.
contract IpcHandler {
    address public owner;
    address public handler;

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    // Guarded setter: only owner can change result handler address.
    // Named "configure*" → is_setter_like ("configure" prefix) → setter.
    function configureResultHandler(address newHandler) external onlyOwner {
        handler = newHandler;
    }

    // Unguarded sink: result execution has no auth guard.
    // Named "execute*" → SINK_HINTS ("execute") → classified as sink.
    // Generates: authority-drift-configureResultHandler-executeResult
    //           + unguarded-sink-executeResult
    //
    // Semantic bug (see sharp_edges.md): _toHash includes localNonce
    // but toTracingId omits it. Receipt.id never matches stored key.
    function executeResult(
        IpcMsgKind kind,
        address to,
        address from,
        uint256 value,
        bytes memory msgData,
        uint256 originalNonce,
        uint256 receiptNonce
    ) external returns (bool) {
        // _toHash includes localNonce (changes between send and receipt)
        bytes32 storedId = keccak256(abi.encode(
            kind, to, from, value, msgData, receiptNonce
        ));

        // toTracingId omits localNonce → receipt.id never matches storedId
        // This means UnrecognizedResult always fires, locking inflightMsgs
        IpcEnvelope memory orig = IpcEnvelope({
            kind: kind,
            to: to,
            from: from,
            value: value,
            message: msgData,
            localNonce: receiptNonce,
            originalNonce: originalNonce
        });
        bytes32 receiptId = keccak256(abi.encode(
            kind, to, from, value, msgData, originalNonce
        ));

        if (receiptId != storedId) revert("UnrecognizedResult");
        // Writes to handler: enables authority-drift finding (shared state with configureResultHandler)
        handler = address(0);
        delete inflightMsgs[storedId];
        return true;
    }

    mapping(bytes32 => IpcEnvelope) public inflightMsgs;
}
