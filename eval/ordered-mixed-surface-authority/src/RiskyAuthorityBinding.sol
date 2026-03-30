pragma solidity ^0.8.20;

contract RiskyAuthorityBinding {
    function executeRescue(address recipient) external {
        payable(recipient).transfer(0);
    }
}
