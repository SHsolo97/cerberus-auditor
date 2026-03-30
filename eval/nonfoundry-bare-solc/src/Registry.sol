// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Registry {
    address public operator;
    address public pendingOperator;

    function setOperator(address newOperator) external {
        operator = newOperator;
    }

    function removeOperator() external {
        operator = address(0);
    }

    // Guard mismatch: setOperator has no guard, removeOperator has no guard
    // Both are callable by anyone, creating authority drift
    function rotate(address newOp) external {
        operator = newOp;
    }
}
