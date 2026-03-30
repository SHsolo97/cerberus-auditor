// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RecoveryVault {
    address public treasury;

    function setTreasury(address newTreasury) external {
        treasury = newTreasury;
    }

    function rescueToken(address token) external {
        treasury = token;
    }
}
