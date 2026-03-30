// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IUpgradeModule {
    function upgradeTo(address nextImplementation) external;
}
