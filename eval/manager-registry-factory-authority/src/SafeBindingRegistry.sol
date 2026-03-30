// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IBindingRegistry.sol";
import "./SafeAuthorityFactory.sol";

contract SafeBindingRegistry is IBindingRegistry {
    SafeAuthorityFactory public factory;

    constructor() {
        factory = new SafeAuthorityFactory();
    }

    function currentFactory() external returns (IAuthorityFactory) {
        return factory;
    }
}
