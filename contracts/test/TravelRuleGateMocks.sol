// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IGroth16Verifier, IAdmittedRootProvider, IGatedTarget} from "../interfaces/ITravelRuleGate.sol";

/// Test-only. Returns a configurable result and records the last call.
contract MockGroth16Verifier is IGroth16Verifier {
    bool public result = true;

    function setResult(bool r) external {
        result = r;
    }

    function verifyProof(uint256[2] calldata, uint256[2][2] calldata, uint256[2] calldata, uint256[] calldata)
        external
        view
        returns (bool)
    {
        return result;
    }
}

contract MockRootProvider is IAdmittedRootProvider {
    bytes32 public root;

    function setRoot(bytes32 r) external {
        root = r;
    }

    function currentRoot() external view returns (bytes32) {
        return root;
    }
}

/// Target that only accepts the gate and records what it received. Can try to
/// re-enter the gate to prove the reentrancy guard.
contract MockGatedTarget is IGatedTarget {
    address public gate;
    uint256 public calls;
    address public lastOperator;
    bytes32 public lastEvidence;
    bytes public lastPayload;
    bytes public reenterData;

    error OnlyGate();

    function setGate(address g) external {
        gate = g;
    }

    function setReenter(bytes calldata data) external {
        reenterData = data;
    }

    function onGatedExecution(address operator, bytes32 evidenceHash, bytes calldata payload) external {
        if (msg.sender != gate) revert OnlyGate();
        calls++;
        lastOperator = operator;
        lastEvidence = evidenceHash;
        lastPayload = payload;
        if (reenterData.length != 0) {
            (bool ok, bytes memory ret) = gate.call(reenterData);
            if (!ok) {
                assembly {
                    revert(add(ret, 32), mload(ret))
                }
            }
        }
    }
}
