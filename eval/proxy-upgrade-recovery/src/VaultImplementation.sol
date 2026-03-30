// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract VaultImplementation {
    function withdraw(address to, uint256 amount) external pure returns (address, uint256) {
        return (to, amount);
    }
}
