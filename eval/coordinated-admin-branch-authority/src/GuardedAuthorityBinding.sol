// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";

contract GuardedAuthorityBinding is IAuthorityBinding {
    modifier onlyOwner() {
        _;
    }

    function rotateAuthority(address) external override onlyOwner {}

    function executeRescue(address, uint256) external override onlyOwner {}
}
