// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface ITokenLike {
    function transfer(address to, uint256 amount) external returns (bool);
}

contract CallbackVault {
    uint256 public settled;
    ITokenLike public token;

    constructor(ITokenLike _token) {
        token = _token;
    }

    function settle(address to, uint256 amount) external {
        settled = amount;
        token.transfer(to, amount);
    }
}
