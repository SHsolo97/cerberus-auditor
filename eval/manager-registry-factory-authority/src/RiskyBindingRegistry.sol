// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IBindingRegistry.sol";
import "./RiskyAuthorityFactory.sol";

contract RiskyBindingRegistry is IBindingRegistry {
    RiskyAuthorityFactory public factory;

    constructor() {
        factory = new RiskyAuthorityFactory();
    }

    function currentFactory() external returns (IAuthorityFactory) {
        return factory;
    }
}
