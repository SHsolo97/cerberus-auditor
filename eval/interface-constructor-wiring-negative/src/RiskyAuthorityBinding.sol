// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";

contract RiskyAuthorityBinding is IAuthorityBinding {
    address public rescueOperator;
    address public treasury;

    function rotateAuthority(address nextOperator) external {
        rescueOperator = nextOperator;
    }

    function executeRescue(address asset, uint256 amount) external {
        require(msg.sender == rescueOperator, "not operator");
        treasury = asset;
        amount;
    }
}
