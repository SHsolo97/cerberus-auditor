// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IBindingManager.sol";
import "./GuardedAuthorityBinding.sol";

contract SafeBindingManager is IBindingManager {
    GuardedAuthorityBinding internal binding;

    constructor() {
        binding = new GuardedAuthorityBinding();
    }

    function currentBinding() external returns (IAuthorityBinding) {
        return binding;
    }
}
