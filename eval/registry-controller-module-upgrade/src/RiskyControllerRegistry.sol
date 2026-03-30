// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IControllerRegistry.sol";
import "./RiskyUpgradeController.sol";

contract RiskyControllerRegistry is IControllerRegistry {
    RiskyUpgradeController public controller;

    constructor() {
        controller = new RiskyUpgradeController();
    }

    function activeController() external returns (IUpgradeController) {
        return controller;
    }
}
