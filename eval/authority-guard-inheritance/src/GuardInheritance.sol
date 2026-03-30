// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ── Parent: guards the sink with onlyAdmin ─────────────────────────────────────
contract BaseVault {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    address public admin;

    modifier onlyAdmin() {
        require(msg.sender == admin, "not admin");
        _;
    }

    function withdraw(uint256 amount) external onlyAdmin {
        payable(msg.sender).transfer(amount);
    }
}

// ── Child: inherits sink WITHOUT overriding guard ────────────────────────────────
// The sink is already guarded by the parent's onlyAdmin modifier.
// No finding expected: authority does not drift.
contract Vault is BaseVault {
    uint256 public balance;

    function deposit() external payable {
        balance += msg.value;
    }
}
