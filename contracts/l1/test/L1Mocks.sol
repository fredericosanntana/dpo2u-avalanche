// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IAllowList} from "../interfaces/IAllowList.sol";
import {IMidnightVerifier} from "../interfaces/IMidnightVerifier.sol";
import {ITeleporterMessenger, ITeleporterReceiver, TeleporterMessageInput} from "../interfaces/ITeleporter.sol";

/// @notice Test double of the Subnet-EVM AllowList precompile. Same role rules: Admin sets any
///         role; Manager only moves addresses between None and Enabled.
contract MockAllowList is IAllowList {
    error CannotModifyAllowList();
    mapping(address => uint256) public roles;

    constructor(address initialAdmin) {
        roles[initialAdmin] = 2;
    }

    function _setRole(address a, uint256 role) internal {
        uint256 caller = roles[msg.sender];
        if (caller == 2) {
            roles[a] = role;
            return;
        }
        if (caller == 3 && role <= 1 && roles[a] <= 1) {
            roles[a] = role;
            return;
        }
        revert CannotModifyAllowList();
    }

    function setAdmin(address a) external { _setRole(a, 2); }
    function setEnabled(address a) external { _setRole(a, 1); }
    function setManager(address a) external { _setRole(a, 3); }
    function setNone(address a) external { _setRole(a, 0); }
    function readAllowList(address a) external view returns (uint256) { return roles[a]; }
}

/// @notice Accepts exactly the (vkHash, proof, publicInputs) tuples registered by the test.
///         Stands in for the MidnightVerifier precompile until phase A2.
contract MockMidnightVerifier is IMidnightVerifier {
    mapping(bytes32 => bool) public accepted;

    function accept(bytes32 vkHash, bytes calldata proof, uint256[] calldata pi) external {
        accepted[keccak256(abi.encode(vkHash, proof, pi))] = true;
    }

    function verify(bytes32 vkHash, bytes calldata proof, uint256[] calldata pi) external view returns (bool) {
        return accepted[keccak256(abi.encode(vkHash, proof, pi))];
    }
}

/// @notice Records sent messages; `deliver` plays the relayer + Warp check on the destination.
contract MockTeleporterMessenger is ITeleporterMessenger {
    struct Sent {
        bytes32 destinationBlockchainID;
        address destinationAddress;
        address origin;
        bytes message;
    }

    Sent[] public sent;

    function sendCrossChainMessage(TeleporterMessageInput calldata m) external returns (bytes32) {
        sent.push(Sent(m.destinationBlockchainID, m.destinationAddress, msg.sender, m.message));
        return keccak256(abi.encode(sent.length, m.message));
    }

    function sentCount() external view returns (uint256) {
        return sent.length;
    }

    function deliver(uint256 i, bytes32 sourceBlockchainID) external {
        Sent memory s = sent[i];
        ITeleporterReceiver(s.destinationAddress).receiveTeleporterMessage(sourceBlockchainID, s.origin, s.message);
    }
}

/// @notice Admission switch for unit tests of gate-restricted assets.
contract MockAdmissionGate {
    mapping(address => bool) public isAdmitted;

    function set(address a, bool v) external {
        isAdmitted[a] = v;
    }
}
