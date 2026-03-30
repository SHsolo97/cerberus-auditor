// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "./IAuthorityRouter.sol";

contract MultiImplementerVault {
    IAuthorityRouter public authorityRouter;

    constructor(IAuthorityRouter router_) {
        authorityRouter = router_;
    }

    function rotateAuthority(address nextOperator) external {
        authorityRouter.rotateAuthority(nextOperator);
    }

    function executeRescue(address asset, uint256 amount) external {
        authorityRouter.executeRescue(asset, amount);
    }
}
