// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IBridgeEndpoint {
    function finalize(bytes calldata payload) external;
}
