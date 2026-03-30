// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";

contract ReserveAuthorityBinding is IAuthorityBinding {
    address public operator;

    modifier onlyOperator() {
        require(msg.sender == operator, "operator only");
        _;
    }

    function rotateAuthority(address nextOperator) external override onlyOperator {
        operator = nextOperator;
    }

    function executeRescue(address, uint256) external override onlyOperator {}
}
