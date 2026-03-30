// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";
import "./RiskyAuthorityBinding.sol";
import "./GuardedAuthorityBinding.sol";

contract WiredGuardedVault {
    IAuthorityBinding public authorityBinding;

    constructor() {
        authorityBinding = new GuardedAuthorityBinding();
    }

    function rotateAuthority(address nextOperator) external {
        authorityBinding.rotateAuthority(nextOperator);
    }

    function executeRescue(address asset, uint256 amount) external {
        authorityBinding.executeRescue(asset, amount);
    }

    function deployRiskyBinding() external returns (address) {
        return address(new RiskyAuthorityBinding());
    }
}
