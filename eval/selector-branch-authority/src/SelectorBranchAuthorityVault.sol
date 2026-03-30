// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";
import "./GuardedAuthorityBinding.sol";
import "./RiskyAuthorityBinding.sol";

contract SelectorBranchAuthorityVault {
    IAuthorityBinding public authorityBinding;
    bool public riskyMode;

    modifier onlyOwner() {
        _;
    }

    constructor() {
        authorityBinding = new GuardedAuthorityBinding();
    }

    function setRiskyMode(bool nextMode) external onlyOwner {
        riskyMode = nextMode;
    }

    function refreshBinding() external {
        if (riskyMode) {
            authorityBinding = new RiskyAuthorityBinding();
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
