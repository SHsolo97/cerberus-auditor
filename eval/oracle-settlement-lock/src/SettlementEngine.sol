// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ── Oracle that returns a price value ──────────────────────────────────────────
interface IOracle {
    function latestAnswer() external view returns (int256);
}

contract SettlementEngine {
    IOracle public oracle;
    uint256 public lockedPrice;
    uint256 public totalSettled;

    constructor(address _oracle) {
        oracle = IOracle(_oracle);
    }

    function lockPrice() external {
        int256 price = oracle.latestAnswer();
        // BUG: does not validate oracle price before locking.
        // An attacker could have made the oracle return 0 before this call.
        lockedPrice = uint256(price);
    }

    // Vulnerable: reads locked (unvalidated) price in a state-mutating external call.
    // The oracle value was locked earlier without validation — settlement uses stale data.
    function executePayout(address recipient, uint256 amount) external {
        require(lockedPrice > 0, "price not locked");
        uint256 value = (amount * lockedPrice) / 1e18;
        totalSettled += value;
        (bool ok,) = recipient.call{value: amount}("");
        require(ok, "transfer failed");
    }
}
