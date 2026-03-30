// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IBindingManager.sol";
import "./SafeBindingRegistry.sol";

contract SafeBindingManager is IBindingManager {
    SafeBindingRegistry public registry;

    constructor() {
        registry = new SafeBindingRegistry();
    }

    function currentRegistry() external returns (IBindingRegistry) {
        return registry;
    }
}
