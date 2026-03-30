// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";
import "./GuardedAuthorityFactory.sol";
import "./RiskyAuthorityFactory.sol";

contract FactoryRefreshAuthorityVault {
    GuardedAuthorityFactory public factory;
    IAuthorityBinding public authorityBinding;

    modifier onlyOwner() {
        _;
    }

    constructor() {
        factory = new GuardedAuthorityFactory();
        authorityBinding = factory.deployBinding();
    }

    function setFactory(RiskyAuthorityFactory nextFactory) external onlyOwner {
        factory = nextFactory;
    }

    function refreshBinding() external {
        authorityBinding = factory.deployBinding();
    }

    function rotateAuthority(address nextOperator) external {
        authorityBinding.rotateAuthority(nextOperator);
    }

    function executeRescue(address asset, uint256 amount) external {
        authorityBinding.executeRescue(asset, amount);
    }
}
