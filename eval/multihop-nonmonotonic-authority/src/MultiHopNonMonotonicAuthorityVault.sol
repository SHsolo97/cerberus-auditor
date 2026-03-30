pragma solidity ^0.8.20;

import "./GuardedAuthorityBinding.sol";
import "./IAuthorityBinding.sol";
import "./RiskyAuthorityBinding.sol";

contract MultiHopNonMonotonicAuthorityVault {
    address public owner;
    address public guardian;
    address public manager;
    bool public riskyMode;
    bool public selectionArmed;
    bool public promotionReady;
    IAuthorityBinding public authorityBinding;
    IAuthorityBinding public pendingBinding;
    IAuthorityBinding public candidateBinding;

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
        pendingBinding = authorityBinding;
        candidateBinding = authorityBinding;
    }

    function setRiskyMode(bool enabled) external onlyOwner {
        riskyMode = enabled;
    }

    function armSelection(bool enabled) external onlyGuardian {
        selectionArmed = enabled;
    }

    function enablePromotion(bool enabled) external onlyManager {
        require(riskyMode && selectionArmed, "armed");
        promotionReady = enabled;
    }

    function stagePending() external {
        if (riskyMode && selectionArmed) {
            pendingBinding = new RiskyAuthorityBinding();
        } else {
            pendingBinding = authorityBinding;
        }
    }

    function promoteCandidate() external {
        if (promotionReady && selectionArmed) {
            candidateBinding = pendingBinding;
        } else {
            candidateBinding = authorityBinding;
        }
    }

    function activateBinding() external {
        if (promotionReady && selectionArmed) {
            authorityBinding = candidateBinding;
        }
    }

    function executeRescue(address recipient) external {
        authorityBinding.executeRescue(recipient);
    }
}
