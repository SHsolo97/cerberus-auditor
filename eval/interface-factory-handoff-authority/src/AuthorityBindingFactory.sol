// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";
import "./RiskyAuthorityBinding.sol";
import "./GuardedAuthorityBinding.sol";

contract AuthorityBindingFactory {
    function deployRiskyBinding() external returns (IAuthorityBinding) {
        return new RiskyAuthorityBinding();
    }

    function deployGuardedBinding() external returns (IAuthorityBinding) {
        return new GuardedAuthorityBinding();
    }
}
