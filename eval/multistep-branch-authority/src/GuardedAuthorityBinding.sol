// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract GuardedAuthorityBinding {
    address public operator;

    modifier onlyOperator() {
        require(msg.sender == operator, "not operator");
        _;
    }

    constructor() {
        operator = msg.sender;
    }

    function executeRescue() external onlyOperator {}
}
