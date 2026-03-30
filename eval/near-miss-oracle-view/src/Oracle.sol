// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ── Oracle with a view-only function that feeds a settlement ───────────────────
contract Oracle {
    int256 public lastPrice;

    // view — does NOT write to contract state (purely informational)
    function latestAnswer() external view returns (int256) {
        return lastPrice;
    }

    function update(int256 newPrice) external {
        lastPrice = newPrice;
    }
}

// ── Settlement engine that reads the oracle but is correctly fail-closed ─────────
contract SettlementEngine {
    Oracle public oracle;

    constructor(address _oracle) {
        oracle = Oracle(_oracle);
    }

    // Properly validates oracle price before using it
    function settle(address recipient, uint256 amount) external {
        int256 price = oracle.latestAnswer();
        require(price > 0, "invalid price");  // ← fail-closed: zero price reverts
        uint256 value = (amount * uint256(price)) / 1e18;
        (bool ok,) = recipient.call{value: value}("");
        require(ok, "transfer failed");
    }
}
