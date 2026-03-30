// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IPriceOracle {
    function latestRoundData() external view returns (uint80, int256, uint256, uint256, uint80);
}

contract OracleVault {
    address public priceFeed;
    uint256 public redeemed;

    function setPriceFeed(address newPriceFeed) external {
        priceFeed = newPriceFeed;
    }

    function redeem(uint256 amount) external {
        redeemed = amount;
        (bool ok, ) = priceFeed.staticcall(abi.encodeWithSignature("latestRoundData()"));
        require(ok, "oracle read failed");
    }
}
