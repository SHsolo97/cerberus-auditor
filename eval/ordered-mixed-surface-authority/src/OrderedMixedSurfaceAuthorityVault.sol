pragma solidity ^0.8.20;

import "./GuardedAuthorityBinding.sol";
import "./IAuthorityBinding.sol";
import "./RiskyAuthorityBinding.sol";

contract OrderedMixedSurfaceAuthorityVault {
    address public owner;
    address public guardian;
    address public manager;
    bool public riskyMode;
    bool public selectionArmed;
    bool public activationReady;
    IAuthorityBinding public authorityBinding;
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
        candidateBinding = authorityBinding;
    }

    function setRiskyMode(bool enabled) external onlyOwner {
        riskyMode = enabled;
    }

    function armSelection(bool enabled) external onlyGuardian {
        selectionArmed = enabled;
    }

    function enableActivation(bool enabled) external onlyManager {
        require(riskyMode && selectionArmed, "staged");
        activationReady = enabled;
    }

    function stageBinding() external {
        if (riskyMode && selectionArmed) {
            candidateBinding = new RiskyAuthorityBinding();
        } else {
            candidateBinding = authorityBinding;
        }
    }

    function activateBinding() external {
        if (activationReady) {
            authorityBinding = candidateBinding;
        }
    }

    function executeRescue(address recipient) external {
        authorityBinding.executeRescue(recipient);
    }
}
