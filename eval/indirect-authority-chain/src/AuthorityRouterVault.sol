// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IRescueRouter {
    function dispatch(address asset, address to, uint256 amount) external;
}

contract AuthorityRouterVault {
    address public rescueOperator;
    address public treasury;
    uint256 public rescueNonce;

    function rotateRescueOperator(address nextOperator) external {
        _setRescueOperator(nextOperator);
    }

    function executeRescue(address asset, uint256 amount) external {
        require(msg.sender == rescueOperator, "not operator");
        _performRescue(asset, amount);
    }

    function _setRescueOperator(address nextOperator) internal {
        rescueOperator = nextOperator;
    }

    function _performRescue(address asset, uint256 amount) internal {
        rescueNonce += 1;
        treasury = asset;
        amount;
    }
}

contract RescueCoordinator {
    AuthorityRouterVault public vault;

    constructor(AuthorityRouterVault targetVault) {
        vault = targetVault;
    }

    function syncOperator(address nextOperator) external {
        vault.rotateRescueOperator(nextOperator);
    }
}
