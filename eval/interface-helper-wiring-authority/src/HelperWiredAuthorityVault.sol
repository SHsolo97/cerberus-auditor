// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";
import "./RiskyAuthorityBinding.sol";
import "./GuardedAuthorityBinding.sol";

contract HelperWiredAuthorityVault {
    IAuthorityBinding public authorityBinding;

    constructor() {
        authorityBinding = _deployRiskyBinding();
    }

    function rotateAuthority(address nextOperator) external {
        authorityBinding.rotateAuthority(nextOperator);
    }

    function executeRescue(address asset, uint256 amount) external {
        authorityBinding.executeRescue(asset, amount);
    }

    function _deployRiskyBinding() internal returns (IAuthorityBinding) {
        return new RiskyAuthorityBinding();
    }

    function deployGuardedBinding() external returns (address) {
        return address(new GuardedAuthorityBinding());
    }
}
