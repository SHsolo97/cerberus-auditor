// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";
import "./GuardedAuthorityBinding.sol";
import "./ReserveAuthorityBinding.sol";

contract SelectorBranchSafeVault {
    IAuthorityBinding public authorityBinding;
    bool public reserveMode;

    modifier onlyOwner() {
        _;
    }

    constructor() {
        authorityBinding = new GuardedAuthorityBinding();
    }

    function setReserveMode(bool nextMode) external onlyOwner {
        reserveMode = nextMode;
    }

    function refreshBinding() external {
        if (reserveMode) {
            authorityBinding = new ReserveAuthorityBinding();
        } else {
            authorityBinding = new GuardedAuthorityBinding();
        }
    }

    function rotateAuthority(address nextOperator) external {
        authorityBinding.rotateAuthority(nextOperator);
    }

    function executeRescue(address asset, uint256 amount) external {
        authorityBinding.executeRescue(asset, amount);
    }
}
