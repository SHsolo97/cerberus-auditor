// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";
import "./RiskyAuthorityBinding.sol";
import "./GuardedAuthorityBinding.sol";

contract WiredAuthorityVault {
    IAuthorityBinding public authorityBinding;

    constructor() {
        authorityBinding = new RiskyAuthorityBinding();
    }

    function replaceBinding(address nextBinding) external {
        authorityBinding = IAuthorityBinding(nextBinding);
    }

    function rotateAuthority(address nextOperator) external {
        authorityBinding.rotateAuthority(nextOperator);
    }

    function executeRescue(address asset, uint256 amount) external {
        authorityBinding.executeRescue(asset, amount);
    }

    function deployGuardedBinding() external returns (address) {
        return address(new GuardedAuthorityBinding());
    }
}
