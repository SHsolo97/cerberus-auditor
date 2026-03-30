// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityModule.sol";

contract AuthorityModuleImpl is IAuthorityModule {
    address public rescueOperator;
    address public treasury;
    uint256 public rescueNonce;

    function rotateAuthority(address nextOperator) external {
        rescueOperator = nextOperator;
    }

    function executeRescue(address asset, uint256 amount) external {
        require(msg.sender == rescueOperator, "not operator");
        rescueNonce += 1;
        treasury = asset;
        amount;
    }
}
