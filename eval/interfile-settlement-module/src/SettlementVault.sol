// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./SettlementModule.sol";

contract SettlementVault {
    SettlementModule public settlementModule;

    constructor(SettlementModule module_) {
        settlementModule = module_;
    }

    function settleClaim(uint256 shares) external {
        settlementModule.settleClaim(shares);
    }
}
