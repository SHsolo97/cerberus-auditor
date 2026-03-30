// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityFactory.sol";

interface IBindingRegistry {
    function currentFactory() external returns (IAuthorityFactory);
}
