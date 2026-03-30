// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IUpgradeModule.sol";

interface IUpgradeController {
    function activateModule() external returns (IUpgradeModule);
}
