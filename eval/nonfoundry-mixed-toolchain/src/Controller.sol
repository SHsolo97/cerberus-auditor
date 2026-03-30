// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Controller {
    address public admin;
    address public pendingAdmin;

    function changeAdmin(address newAdmin) external {
        admin = newAdmin;
    }

    function setAdmin(address newAdmin) external {
        admin = newAdmin;
    }

    // Guard drift: changeAdmin has no guard, setAdmin has no guard
    function execute(address target, bytes calldata data) external {
        (bool ok,) = target.call(data);
        require(ok);
    }
}
