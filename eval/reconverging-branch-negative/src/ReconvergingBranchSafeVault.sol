pragma solidity ^0.8.20;

import "./GuardedAuthorityBinding.sol";
import "./IAuthorityBinding.sol";
import "./RiskyAuthorityBinding.sol";

contract ReconvergingBranchSafeVault {
    address public owner;
    address public guardian;
    address public manager;
    bool public riskyMode;
    bool public primaryArmed;
    bool public fallbackArmed;
    bool public promotionReady;
    IAuthorityBinding public authorityBinding;
    IAuthorityBinding public primaryBinding;
    IAuthorityBinding public fallbackBinding;
    IAuthorityBinding public candidateBinding;
    IAuthorityBinding public finalBinding;

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    modifier onlyGuardian() {
        require(msg.sender == guardian, "guardian");
        _;
    }

    modifier onlyManager() {
        require(msg.sender == manager, "manager");
        _;
    }

    constructor() {
        owner = msg.sender;
        guardian = msg.sender;
        manager = msg.sender;
        authorityBinding = new GuardedAuthorityBinding(address(this));
        primaryBinding = authorityBinding;
        fallbackBinding = authorityBinding;
        candidateBinding = authorityBinding;
        finalBinding = authorityBinding;
    }

    function setRiskyMode(bool enabled) external onlyOwner {
        riskyMode = enabled;
    }

    function armPrimary(bool enabled) external onlyGuardian {
        primaryArmed = enabled;
    }

    function armFallback(bool enabled) external onlyGuardian {
        fallbackArmed = enabled;
    }

    function enablePromotion(bool enabled) external onlyManager {
        require(riskyMode && primaryArmed, "primary");
        promotionReady = enabled;
    }

    function stagePrimary() external {
        if (riskyMode && primaryArmed) {
            primaryBinding = new RiskyAuthorityBinding();
        } else {
            primaryBinding = authorityBinding;
        }
    }

    function stageFallback() external {
        if (fallbackArmed) {
            fallbackBinding = authorityBinding;
        }
    }

    function chooseCandidate() external {
        if (promotionReady && primaryArmed) {
            candidateBinding = primaryBinding;
            primaryArmed = false;
            promotionReady = false;
            riskyMode = false;
        } else if (fallbackArmed) {
            candidateBinding = fallbackBinding;
        } else {
            candidateBinding = authorityBinding;
        }
    }

    function finalizeCandidate() external {
        if (promotionReady) {
            finalBinding = candidateBinding;
        } else {
            finalBinding = authorityBinding;
        }
    }

    function activateBinding() external {
        if (promotionReady && primaryArmed) {
            authorityBinding = finalBinding;
        }
    }

    function executeRescue(address recipient) external {
        authorityBinding.executeRescue(recipient);
    }
}
