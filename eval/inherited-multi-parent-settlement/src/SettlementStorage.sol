// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SettlementStorage {
    address public bridgeMessenger;
    uint256 public settledShares;
    uint256 public settlementNonce;
}
