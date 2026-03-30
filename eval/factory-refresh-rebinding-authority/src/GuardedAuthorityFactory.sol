// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";
import "./GuardedAuthorityBinding.sol";

contract GuardedAuthorityFactory {
    function deployBinding() external returns (IAuthorityBinding) {
        return new GuardedAuthorityBinding();
    }
}
