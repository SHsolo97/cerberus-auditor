pragma solidity ^0.8.20;

import "./IAuthorityBinding.sol";

contract GuardedAuthorityBinding is IAuthorityBinding {
    address public owner;

    constructor(address owner_) {
        owner = owner_;
    }

    function executeRescue(address recipient) external override {
        require(msg.sender == owner, "owner");
        require(recipient != address(0), "recipient");
    }
}
