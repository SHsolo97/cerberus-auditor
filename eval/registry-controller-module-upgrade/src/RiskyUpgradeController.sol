// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IUpgradeController.sol";
import "./RiskyUpgradeModule.sol";

contract RiskyUpgradeController is IUpgradeController {
    function activateModule() external returns (IUpgradeModule) {
        return new RiskyUpgradeModule();
    }
}
