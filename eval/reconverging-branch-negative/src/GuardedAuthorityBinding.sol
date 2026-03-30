pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";

contract GuardedAuthorityBinding is IAuthorityBinding {
    address public immutable vault;

    constructor(address vault_) {
        vault = vault_;
    }

    function executeRescue(address recipient) external override {
        require(msg.sender == vault, "vault");
        require(recipient != address(0), "recipient");
    }
}
