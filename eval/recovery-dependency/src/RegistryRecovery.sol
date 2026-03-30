// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract RegistryRecovery {
    address public registry;
    address public treasury;

    function rotateRegistry(address newRegistry) external {
        registry = newRegistry;
    }

    function recoverAssets(address newTreasury) external {
        treasury = newTreasury;
    }
}
