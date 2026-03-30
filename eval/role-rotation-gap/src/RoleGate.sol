// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ── Simple AccessControl stub ──────────────────────────────────────────────────
abstract contract AccessControl {
    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;
    bytes32 public constant SINK_ROLE = keccak256("SINK_ROLE");

    mapping(bytes32 => mapping(address => bool)) public roles;

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return roles[role][account];
    }

    function grantRole(bytes32 role, address account) internal {
        roles[role][account] = true;
    }

    function revokeRole(bytes32 role, address account) internal {
        roles[role][account] = false;
    }
}

// ── Vault guarded by SINK_ROLE but rotation only touches ADMIN_ROLE ────────────
// revokeRole(ADMIN) does NOT revoke SINK_ROLE — the sink remains callable.
contract RoleVault is AccessControl {
    uint256 public balance;

    modifier onlySinkRole() {
        require(hasRole(SINK_ROLE, msg.sender), "missing sink role");
        _;
    }

    function withdraw(uint256 amount) external onlySinkRole {
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
    }

    // Admin can rotate admin — but SINK_ROLE holder is independent
    function rotateAdmin(address newAdmin) external {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender), "not admin");
        revokeRole(DEFAULT_ADMIN_ROLE, msg.sender);
        grantRole(DEFAULT_ADMIN_ROLE, newAdmin);
    }

    receive() external payable {
        balance += msg.value;
    }
}
