// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SettlementModule {
    address public bridgeMessenger;
    uint256 public settledShares;
    uint256 public settlementNonce;

    function setBridgeMessenger(address nextBridgeMessenger) external {
        bridgeMessenger = nextBridgeMessenger;
    }

    function settleClaim(uint256 shares) external {
        settledShares = shares;
        settlementNonce += 1;
        (bool ok, ) = bridgeMessenger.call(abi.encodeWithSignature("finalize(bytes)", ""));
        require(ok, "bridge settlement failed");
    }
}
