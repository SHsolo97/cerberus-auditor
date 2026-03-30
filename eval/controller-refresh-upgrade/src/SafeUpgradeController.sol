// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IUpgradeController.sol";
import "./SafeUpgradeModule.sol";

contract SafeUpgradeController is IUpgradeController {
    function activateModule() external returns (IUpgradeModule) {
        return new SafeUpgradeModule();
    }
}
