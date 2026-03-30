// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";
import "./IBindingManager.sol";
import "./SafeBindingManager.sol";

contract InterfaceManagerBranchVault {
    IBindingManager public manager;
    IAuthorityBinding public authorityBinding;

    modifier onlyOwner() {
        _;
    }

    constructor() {
        manager = new SafeBindingManager();
        authorityBinding = manager.currentBinding();
    }

    function setManager(IBindingManager nextManager) external onlyOwner {
        manager = nextManager;
    }

    function refreshBinding() external {
        authorityBinding = manager.currentBinding();
    }

    function rotateAuthority(address nextOperator) external {
        authorityBinding.rotateAuthority(nextOperator);
    }

    function executeRescue(address asset, uint256 amount) external {
        authorityBinding.executeRescue(asset, amount);
    }
}
