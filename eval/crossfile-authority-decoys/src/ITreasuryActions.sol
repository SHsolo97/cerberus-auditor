// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITreasuryActions {
    function rescueToken(address replacementTreasury) external;
}
