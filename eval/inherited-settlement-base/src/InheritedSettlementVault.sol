// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./SettlementBase.sol";

contract InheritedSettlementVault is SettlementBase {
    function setBridgeMessenger(address nextBridgeMessenger) external {
        bridgeMessenger = nextBridgeMessenger;
    }

    function settleClaim(uint256 shares) external {
        _executeSettlement(shares);
    }
}
