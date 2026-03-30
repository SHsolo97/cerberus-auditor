// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ── Vulnerable vault with unguarded reentrant callback ─────────────────────────
contract Vault {
    mapping(address => uint256) public balanceOf;
    bool internal unlocked;

    // No reentrancy guard on withdrawAll
    function withdrawAll() external {
        require(!unlocked, "reentrant");
        unlocked = true;
        uint256 amount = balanceOf[msg.sender];
        balanceOf[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        unlocked = false;
    }

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }
}
