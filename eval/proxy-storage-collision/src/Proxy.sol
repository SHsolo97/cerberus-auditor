// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ── Minimal proxy that stores admin at slot 0 ─────────────────────────────────
contract MinimalProxy {
    address public admin;
    address public implementation;

    function setAdmin(address newAdmin) external {
        require(msg.sender == admin, "not admin");
        admin = newAdmin;
    }
}

// ── Vulnerable implementation that writes to slot 0 (the proxy's admin slot) ──
contract Impl {
    // storage slot 0 — collides with proxy.admin
    address public owner;

    modifier onlyOwner() {
        require(msg.sender == owner, "not owner");
        _;
    }

    // This function lets anyone overwrite the proxy's admin slot
    function setOwner(address newOwner) external {
        owner = newOwner;
    }

    function drain() external onlyOwner {
        payable(msg.sender).transfer(address(this).balance);
    }

    receive() external payable {}
}
