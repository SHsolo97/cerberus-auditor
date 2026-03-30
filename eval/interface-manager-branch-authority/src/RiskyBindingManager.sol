// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IBindingManager.sol";
import "./RiskyAuthorityBinding.sol";

contract RiskyBindingManager is IBindingManager {
    RiskyAuthorityBinding internal binding;

    constructor() {
        binding = new RiskyAuthorityBinding();
    }

    function currentBinding() external returns (IAuthorityBinding) {
        return binding;
    }
}
