// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IUpgradeModule.sol";

contract SafeUpgradeModule is IUpgradeModule {
    modifier onlyOwner() {
        _;
    }

    function upgradeTo(address nextImplementation) external onlyOwner {
        nextImplementation;
    }
}
