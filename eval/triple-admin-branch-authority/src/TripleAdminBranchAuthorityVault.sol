pragma solidity ^0.8.20;

import "./GuardedAuthorityBinding.sol";
import "./IAuthorityBinding.sol";
import "./RiskyAuthorityBinding.sol";

contract TripleAdminBranchAuthorityVault {
    address public owner;
    bool public riskyMode;
    bool public emergencyArmed;
    bool public refreshReady;
    IAuthorityBinding public authorityBinding;
    IAuthorityBinding public candidateBinding;

    modifier onlyOwner() {
        require(msg.sender == owner, "owner");
        _;
    }

    constructor() {
        owner = msg.sender;
        authorityBinding = new GuardedAuthorityBinding(address(this));
        candidateBinding = authorityBinding;
    }

    function setRiskyMode(bool enabled) external onlyOwner {
        riskyMode = enabled;
    }

    function armEmergency(bool enabled) external onlyOwner {
        emergencyArmed = enabled;
    }

    function configureRefresh(bool enabled) external onlyOwner {
        refreshReady = enabled;
    }

    function selectBinding() external {
        if (riskyMode && emergencyArmed && refreshReady) {
            candidateBinding = new RiskyAuthorityBinding();
        } else {
            candidateBinding = authorityBinding;
        }
    }

    function activateBinding() external {
        authorityBinding = candidateBinding;
    }

    function executeRescue(address recipient) external {
        authorityBinding.executeRescue(recipient);
    }
}
