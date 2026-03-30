// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IUpgradeModule.sol";

contract RiskyUpgradeModule is IUpgradeModule {
    address public implementation;

    function upgradeTo(address nextImplementation) external {
        implementation = nextImplementation;
    }
}
