// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IVaultImplementation {
    function withdraw(address to, uint256 amount) external;
}

contract UpgradeableVault {
    address public implementation;
    address public treasury;

    function rotateImplementation(address newImplementation) external {
        implementation = newImplementation;
    }

    function upgradeTo(address nextImplementation) external {
        implementation = nextImplementation;
    }

    function recoverTreasury(address newTreasury) external {
        treasury = newTreasury;
    }
}
