// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IBindingRegistry.sol";

interface IBindingManager {
    function currentRegistry() external returns (IBindingRegistry);
}
