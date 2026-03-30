// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IUpgradeController.sol";
import "./IUpgradeModule.sol";
import "./SafeUpgradeController.sol";
import "./RiskyUpgradeController.sol";

contract ControllerRefreshUpgradeVault {
    SafeUpgradeController public controller;
    IUpgradeModule public upgradeModule;

    modifier onlyOwner() {
        _;
    }

    constructor() {
        controller = new SafeUpgradeController();
        upgradeModule = controller.activateModule();
    }

    function setController(RiskyUpgradeController nextController) external onlyOwner {
        controller = nextController;
    }

    function refreshModule() external {
        upgradeModule = controller.activateModule();
    }

    function upgradeVault(address nextImplementation) external {
        upgradeModule.upgradeTo(nextImplementation);
    }
}
