// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SettlementBase {
    address public bridgeMessenger;
    uint256 public settledShares;
    uint256 public settlementNonce;

    function _executeSettlement(uint256 shares) internal {
        settledShares = shares;
        settlementNonce += 1;
        (bool ok, ) = bridgeMessenger.call(abi.encodeWithSignature("finalize(bytes)", ""));
        require(ok, "bridge settlement failed");
    }
}
