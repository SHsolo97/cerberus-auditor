// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockOracle {
    function latestRoundData() external pure returns (uint80, int256, uint256, uint256, uint80) {
        return (1, 1e8, 0, block.timestamp, 1);
    }
}
