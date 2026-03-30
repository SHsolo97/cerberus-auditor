// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IBindingManager.sol";
import "./RiskyBindingRegistry.sol";

contract RiskyBindingManager is IBindingManager {
    RiskyBindingRegistry public registry;

    constructor() {
        registry = new RiskyBindingRegistry();
    }

    function currentRegistry() external returns (IBindingRegistry) {
        return registry;
    }
}
