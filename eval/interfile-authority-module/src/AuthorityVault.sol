// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./AuthorityModule.sol";

contract AuthorityVault {
    AuthorityModule public authorityModule;

    constructor(AuthorityModule module_) {
        authorityModule = module_;
    }

    function rotateAuthority(address nextOperator) external {
        authorityModule.rotateAuthority(nextOperator);
    }

    function executeRescue(address asset, uint256 amount) external {
        authorityModule.executeRescue(asset, amount);
    }
}
