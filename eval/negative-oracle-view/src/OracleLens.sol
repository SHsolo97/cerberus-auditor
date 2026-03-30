// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IOracleView {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

contract OracleLens {
    address public priceFeed;

    function setPriceFeed(address newPriceFeed) external {
        priceFeed = newPriceFeed;
    }

    function quote() external view returns (int256 answer) {
        (, answer, , , ) = IOracleView(priceFeed).latestRoundData();
    }
}
