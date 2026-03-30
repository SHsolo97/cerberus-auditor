// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";
import "./IAuthorityFactory.sol";
import "./IBindingRegistry.sol";
import "./SafeBindingManager.sol";
import "./RiskyBindingManager.sol";

contract ManagerRegistryFactoryAuthorityVault {
    SafeBindingManager public manager;
    IBindingRegistry public registry;
    IAuthorityFactory public factory;
    IAuthorityBinding public authorityBinding;

    modifier onlyOwner() {
        _;
    }

    constructor() {
        manager = new SafeBindingManager();
        registry = manager.currentRegistry();
        factory = registry.currentFactory();
        authorityBinding = factory.deployBinding();
    }

    function setManager(RiskyBindingManager nextManager) external onlyOwner {
        manager = nextManager;
    }

    function refreshRegistry() external {
        registry = manager.currentRegistry();
    }

    function refreshFactory() external {
        factory = registry.currentFactory();
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
