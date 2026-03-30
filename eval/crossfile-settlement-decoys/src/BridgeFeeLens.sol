// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BridgeFeeLens {
    function quoteBridgeFee(uint256 amount) external pure returns (uint256) {
        return amount / 100;
    }
}
