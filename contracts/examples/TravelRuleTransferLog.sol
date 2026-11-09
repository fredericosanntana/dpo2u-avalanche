// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IGatedTarget} from "../interfaces/ITravelRuleGate.sol";

/// @title TravelRuleTransferLog — example target of DPO2UTravelRuleGate
/// @notice Records each operator action the gate let through: who, under which sealed
///         evidence, and the hash of the Travel Rule payload (never the payload itself).
///         Stands in for a real settlement/rebalance target on testnet.
/// @dev Example only (not audited). The gate is bound once by the deployer, because the gate
///      and its target each need the other's address at deploy time.
contract TravelRuleTransferLog is IGatedTarget {
    error NotGate();
    error AlreadyBound();
    error NotDeployer();

    address public immutable deployer;
    address public gate;
    uint256 public count;

    event GateBound(address indexed gate);
    event Logged(uint256 indexed n, address indexed operator, bytes32 indexed evidenceHash, bytes32 payloadHash);

    constructor() {
        deployer = msg.sender;
    }

    function bindGate(address gate_) external {
        if (msg.sender != deployer) revert NotDeployer();
        if (gate != address(0)) revert AlreadyBound();
        gate = gate_;
        emit GateBound(gate_);
    }

    function onGatedExecution(address operator, bytes32 evidenceHash, bytes calldata payload) external {
        if (msg.sender != gate || gate == address(0)) revert NotGate();
        emit Logged(++count, operator, evidenceHash, keccak256(payload));
    }
}
