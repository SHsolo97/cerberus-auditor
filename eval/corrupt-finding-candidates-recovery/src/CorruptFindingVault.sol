// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CorruptFindingVault {
    address public bridgeEndpoint;
    uint256 public settledDebt;

    function setBridgeEndpoint(address newBridgeEndpoint) external {
        bridgeEndpoint = newBridgeEndpoint;
    }

    function settleBridge(uint256 amount) external {
        settledDebt = amount;
        (bool ok, ) = bridgeEndpoint.call(abi.encodeWithSignature("finalize(bytes)", ""));
        require(ok, "bridge settlement failed");
    }
}
