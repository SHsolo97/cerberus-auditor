// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GuardedRescueHelper {
    address public helperTreasury;

    modifier onlyOwner() {
        _;
    }

    function rescueMirror(address replacementTreasury) external onlyOwner {
        helperTreasury = replacementTreasury;
    }
}
