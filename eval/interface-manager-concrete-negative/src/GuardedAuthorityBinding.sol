// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";

contract GuardedAuthorityBinding is IAuthorityBinding {
    address public operator;

    modifier onlyOperator() {
        _;
    }

    function rotateAuthority(address nextOperator) external onlyOperator {
        operator = nextOperator;
    }

    function executeRescue(address asset, uint256 amount) external onlyOperator {
        asset;
        amount;
    }
}
