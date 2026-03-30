// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityModule.sol";

contract InterfaceAuthorityVault {
    IAuthorityModule public authorityModule;

    constructor(IAuthorityModule module_) {
        authorityModule = module_;
    }

    function rotateAuthority(address nextOperator) external {
        authorityModule.rotateAuthority(nextOperator);
    }

    function executeRescue(address asset, uint256 amount) external {
        authorityModule.executeRescue(asset, amount);
    }
}
