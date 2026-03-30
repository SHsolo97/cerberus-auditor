// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";
import "./GuardedAuthorityBinding.sol";
import "./RiskyAuthorityBinding.sol";

contract MultiStepBranchSafeVault {
    bool public riskyMode;
    bool public emergencyArmed;
    IAuthorityBinding public candidateBinding;
    IAuthorityBinding public authorityBinding;

    constructor() {
        emergencyArmed = false;
        IAuthorityBinding safeBinding = IAuthorityBinding(address(new GuardedAuthorityBinding()));
        candidateBinding = safeBinding;
        authorityBinding = safeBinding;
    }

    function setRiskyMode(bool risky) external {
        riskyMode = risky;
    }

    function selectBinding() external {
        if (riskyMode && emergencyArmed) {
            candidateBinding = IAuthorityBinding(address(new RiskyAuthorityBinding()));
        } else {
            candidateBinding = IAuthorityBinding(address(new GuardedAuthorityBinding()));
        }
    }

    function activateBinding() external {
        authorityBinding = candidateBinding;
    }

    function executeRescue() external {
        authorityBinding.executeRescue();
    }
}
