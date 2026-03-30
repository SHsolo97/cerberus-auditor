// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./GuardedAuthorityBinding.sol";
import "./IAuthorityBinding.sol";
import "./RiskyAuthorityBinding.sol";

contract CoordinatedAdminBranchAuthorityVault {
    IAuthorityBinding public authorityBinding;
    IAuthorityBinding public candidateBinding;
    bool public riskyMode;
    bool public emergencyArmed;

    modifier onlyOwner() {
        _;
    }

    constructor() {
        authorityBinding = new GuardedAuthorityBinding();
        candidateBinding = authorityBinding;
    }

    function setRiskyMode(bool nextMode) external onlyOwner {
        riskyMode = nextMode;
    }

    function armEmergency(bool nextMode) external onlyOwner {
        emergencyArmed = nextMode;
    }

    function selectBinding() external {
        if (riskyMode && emergencyArmed) {
            candidateBinding = new RiskyAuthorityBinding();
        } else {
            candidateBinding = new GuardedAuthorityBinding();
        }
    }

    function activateBinding() external {
        authorityBinding = candidateBinding;
    }

    function rotateAuthority(address nextOperator) external {
        authorityBinding.rotateAuthority(nextOperator);
    }

    function executeRescue(address asset, uint256 amount) external {
        authorityBinding.executeRescue(asset, amount);
    }
}
