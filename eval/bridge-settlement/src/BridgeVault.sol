// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IBridgeMessenger {
    function finalize(bytes calldata payload) external;
}

contract BridgeVault {
    address public bridgeMessenger;
    uint256 public settledDebt;

    function setBridgeMessenger(address newBridgeMessenger) external {
        bridgeMessenger = newBridgeMessenger;
    }

    function settleBridge(uint256 amount) external {
        settledDebt = amount;
        (bool ok, ) = bridgeMessenger.call(abi.encodeWithSignature("finalize(bytes)", ""));
        require(ok, "bridge settlement failed");
    }
}
