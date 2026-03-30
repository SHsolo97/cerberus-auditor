// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";

contract RiskyAuthorityBinding is IAuthorityBinding {
    address public operator;

    function rotateAuthority(address nextOperator) external override {
        operator = nextOperator;
    }

    function executeRescue(address, uint256) external override {}
}
