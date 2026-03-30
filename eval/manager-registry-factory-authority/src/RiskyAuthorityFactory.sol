// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityFactory.sol";
import "./RiskyAuthorityBinding.sol";

contract RiskyAuthorityFactory is IAuthorityFactory {
    function deployBinding() external returns (IAuthorityBinding) {
        return new RiskyAuthorityBinding();
    }
}
