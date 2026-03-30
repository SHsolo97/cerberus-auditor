// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract TokenManager {
    address public governor;
    address public pendingGovernor;

    constructor() {
        governor = msg.sender;
    }

    // Guard mismatch: both callable by anyone
    function proposeGovernor(address newGovernor) external {
        pendingGovernor = newGovernor;
    }

    function acceptGovernor() external {
        require(msg.sender == pendingGovernor, "!pending");
        governor = msg.sender;
        pendingGovernor = address(0);
    }

    // Unguarded sink — anyone can mint
    function rescueTokens(address token, address to, uint256 amount) external {
        // No access control
        (bool ok,) = token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
        require(ok, "transfer failed");
    }
}
