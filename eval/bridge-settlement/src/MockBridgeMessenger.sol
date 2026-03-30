// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockBridgeMessenger {
    function finalize(bytes calldata payload) external pure returns (bytes32) {
        return keccak256(payload);
    }
}
