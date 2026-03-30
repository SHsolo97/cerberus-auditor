// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

interface IBridgeAdapter {
    function finalizeRedemption(bytes calldata payload) external;
}

contract SettlementRouterVault {
    address public bridgeAdapter;
    uint256 public settledShares;
    uint256 public redemptionNonce;

    function setBridgeAdapter(address nextAdapter) external {
        _setBridgeAdapter(nextAdapter);
    }

    function settleRedemption(uint256 shares) external {
        _stageSettlement(shares);
    }

    function _setBridgeAdapter(address nextAdapter) internal {
        bridgeAdapter = nextAdapter;
    }

    function _stageSettlement(uint256 shares) internal {
        settledShares = shares;
        redemptionNonce += 1;
        _dispatchSettlement();
    }

    function _dispatchSettlement() internal {
        (bool ok, ) = bridgeAdapter.call(abi.encodeWithSignature("finalizeRedemption(bytes)", ""));
        require(ok, "adapter failed");
    }
}

contract SettlementViewRouter {
    function adapterOf(SettlementRouterVault vault) external view returns (address) {
        return vault.bridgeAdapter();
    }
}
