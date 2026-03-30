// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract SeverityAuthorityVault {
    bytes32 public constant TREASURY_ROLE = keccak256("TREASURY_ROLE");

    address public treasury;
    address public implementation;

    modifier onlyOwner() {
        _;
    }

    modifier onlyRole(bytes32) {
        _;
    }

    function setTreasury(address newTreasury) external onlyOwner {
        treasury = newTreasury;
    }

    function rescueToken(address replacementTreasury) external onlyRole(TREASURY_ROLE) {
        treasury = replacementTreasury;
    }

    function recoverTreasury(address fallbackTreasury) external onlyOwner {
        treasury = fallbackTreasury;
    }

    function rotateImplementation(address newImplementation) external {
        implementation = newImplementation;
    }

    function upgradeTo(address nextImplementation) external {
        implementation = nextImplementation;
    }
}
