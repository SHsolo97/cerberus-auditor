// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IBridgeEndpoint {
    function finalize(bytes calldata payload) external;
}

interface IRateView {
    function currentValue() external view returns (int256);
}

contract MixedSettlementVault {
    address public bridge;
    address public rateLens;
    uint256 public settledDebt;

    function setBridge(address newBridge) external {
        bridge = newBridge;
    }

    function setRateLens(address newRateLens) external {
        rateLens = newRateLens;
    }

    function settleBridge(uint256 amount) external {
        settledDebt = amount;
        (bool ok, ) = bridge.call(abi.encodeWithSignature("finalize(bytes)", ""));
        require(ok, "bridge settlement failed");
    }

    function quote() external view returns (int256 answer) {
        answer = IRateView(rateLens).currentValue();
    }
}
