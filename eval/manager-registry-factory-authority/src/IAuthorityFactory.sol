// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";

interface IAuthorityFactory {
    function deployBinding() external returns (IAuthorityBinding);
}
