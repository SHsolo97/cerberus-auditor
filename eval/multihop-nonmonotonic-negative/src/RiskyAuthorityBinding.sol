pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";

contract RiskyAuthorityBinding is IAuthorityBinding {
    function executeRescue(address recipient) external override {
        require(recipient != address(0), "recipient");
    }
}
