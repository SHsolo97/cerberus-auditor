// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";

interface IBindingManager {
    function currentBinding() external returns (IAuthorityBinding);
}
