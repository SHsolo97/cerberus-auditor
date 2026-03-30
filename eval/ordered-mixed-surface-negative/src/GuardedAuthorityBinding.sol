pragma solidity ^0.8.20;

contract GuardedAuthorityBinding {
    address public vault;

    constructor(address vault_) {
        vault = vault_;
    }

    function executeRescue(address recipient) external {
        require(msg.sender == vault, "vault");
        payable(recipient).transfer(0);
    }
}
