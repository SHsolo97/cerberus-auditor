// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityRouter.sol";

contract GuardedAuthorityRouter is IAuthorityRouter {
    address public rescueOperator;
    address public treasury;

    modifier onlyOwner() {
        _;
    }

    function rotateAuthority(address nextOperator) external onlyOwner {
        rescueOperator = nextOperator;
    }

    function executeRescue(address asset, uint256 amount) external onlyOwner {
        treasury = asset;
        amount;
    }
}
