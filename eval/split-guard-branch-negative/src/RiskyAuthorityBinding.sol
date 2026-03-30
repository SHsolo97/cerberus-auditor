// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";

contract RiskyAuthorityBinding is IAuthorityBinding {
    function rotateAuthority(address) external override {}

    function executeRescue(address, uint256) external override {}
}
