// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";
import "./RiskyAuthorityBinding.sol";

contract RiskyAuthorityFactory {
    function deployBinding() external returns (IAuthorityBinding) {
        return new RiskyAuthorityBinding();
    }
}
