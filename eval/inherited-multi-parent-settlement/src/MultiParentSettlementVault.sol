// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./SettlementExecutor.sol";
import "./SettlementAdmin.sol";

contract MultiParentSettlementVault is SettlementExecutor, SettlementAdmin {
    function settleClaim(uint256 shares) external {
        _executeSettlement(shares);
    }
}
