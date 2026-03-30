// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./SettlementStorage.sol";

contract SettlementAdmin is SettlementStorage {
    function setBridgeMessenger(address nextBridgeMessenger) external {
        bridgeMessenger = nextBridgeMessenger;
    }
}
