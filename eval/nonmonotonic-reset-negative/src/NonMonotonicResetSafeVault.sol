pragma solidity ^0.8.20;

import "./GuardedAuthorityBinding.sol";
import "./IAuthorityBinding.sol";
import "./RiskyAuthorityBinding.sol";

contract NonMonotonicResetSafeVault {
    address public owner;
    address public guardian;
    address public manager;
    bool public riskyMode;
    bool public stagingArmed;
    bool public relayReady;
    IAuthorityBinding public authorityBinding;

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
    }

    function setRiskyMode(bool enabled) external onlyOwner {
        riskyMode = enabled;
    }

    function armStaging(bool enabled) external onlyGuardian {
        stagingArmed = enabled;
    }

    function enableRelay(bool enabled) external onlyManager {
        require(riskyMode && stagingArmed, "staged");
        relayReady = enabled;
        stagingArmed = false;
    }

    function refreshBinding() external {
        if (riskyMode && stagingArmed && relayReady) {
            authorityBinding = new RiskyAuthorityBinding();
        }
    }

    function executeRescue(address recipient) external {
        authorityBinding.executeRescue(recipient);
    }
}
