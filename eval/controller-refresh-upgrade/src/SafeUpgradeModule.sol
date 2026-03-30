// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IUpgradeModule.sol";

contract SafeUpgradeModule is IUpgradeModule {
    address public owner;
    address public implementation;

    constructor() {
        owner = msg.sender;
    }

    function upgradeTo(address nextImplementation) external {
        require(msg.sender == owner, "owner");
        implementation = nextImplementation;
    }
}
