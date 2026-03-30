// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";

contract GuardedAuthorityBinding is IAuthorityBinding {
    address public owner;
    address public operator;

    constructor() {
        owner = msg.sender;
        operator = msg.sender;
    }

    function rotateAuthority(address nextOperator) external {
        require(msg.sender == owner, "owner");
        operator = nextOperator;
    }

    function executeRescue(address asset, uint256 amount) external {
        require(msg.sender == owner, "owner");
        operator = asset;
        if (amount > 0) {
            operator = msg.sender;
        }
    }
}
