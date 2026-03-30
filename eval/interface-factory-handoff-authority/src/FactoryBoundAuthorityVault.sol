// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";
import "./AuthorityBindingFactory.sol";

contract FactoryBoundAuthorityVault {
    AuthorityBindingFactory public factory;
    IAuthorityBinding public authorityBinding;

    constructor(AuthorityBindingFactory factory_) {
        factory = factory_;
        authorityBinding = factory_.deployRiskyBinding();
    }

    function rotateAuthority(address nextOperator) external {
        authorityBinding.rotateAuthority(nextOperator);
    }

    function executeRescue(address asset, uint256 amount) external {
        authorityBinding.executeRescue(asset, amount);
    }
}
