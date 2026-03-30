// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";

contract GuardedAuthorityBinding is IAuthorityBinding {
    modifier onlyOwner() {
        _;
    }

    function rotateAuthority(address nextOperator) external onlyOwner {
        nextOperator;
    }

    function executeRescue(address asset, uint256 amount) external onlyOwner {
        asset;
        amount;
    }
}
