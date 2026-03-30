// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IAuthorityModule {
    function rotateAuthority(address nextOperator) external;
    function executeRescue(address asset, uint256 amount) external;
}
