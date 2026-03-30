// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IControllerRegistry.sol";
import "./SafeUpgradeController.sol";

contract SafeControllerRegistry is IControllerRegistry {
    SafeUpgradeController public controller;

    constructor() {
        controller = new SafeUpgradeController();
    }

    function activeController() external returns (IUpgradeController) {
        return controller;
    }
}
