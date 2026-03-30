pragma solidity ^0.8.20;

interface IAuthorityBinding {
    function executeRescue(address recipient) external;
}
