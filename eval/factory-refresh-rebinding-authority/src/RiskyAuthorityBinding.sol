// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";

contract RiskyAuthorityBinding is IAuthorityBinding {
    address public operator;

    function rotateAuthority(address nextOperator) external {
        operator = nextOperator;
    }

    function executeRescue(address asset, uint256 amount) external {
        operator = asset;
        if (amount > 0) {
            operator = msg.sender;
        }
    }
}
