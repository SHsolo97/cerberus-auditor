// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IControllerRegistry.sol";
import "./IUpgradeController.sol";
import "./IUpgradeModule.sol";
import "./SafeControllerRegistry.sol";
import "./RiskyControllerRegistry.sol";

contract RegistryControllerModuleVault {
    SafeControllerRegistry public registry;
    IUpgradeController public controller;
    IUpgradeModule public upgradeModule;

    modifier onlyOwner() {
        _;
    }

    constructor() {
        registry = new SafeControllerRegistry();
        controller = registry.activeController();
        upgradeModule = controller.activateModule();
    }

    function setRegistry(RiskyControllerRegistry nextRegistry) external onlyOwner {
        registry = nextRegistry;
    }

    function refreshController() external {
        controller = registry.activeController();
    }

    function refreshModule() external {
        upgradeModule = controller.activateModule();
    }

    function upgradeVault(address nextImplementation) external {
        upgradeModule.upgradeTo(nextImplementation);
    }
}
