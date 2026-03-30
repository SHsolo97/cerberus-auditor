// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityFactory.sol";
import "./GuardedAuthorityBinding.sol";

contract SafeAuthorityFactory is IAuthorityFactory {
    function deployBinding() external returns (IAuthorityBinding) {
        return new GuardedAuthorityBinding();
    }
}
