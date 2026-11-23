// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ITeleporterReceiver} from "./interfaces/ITeleporter.sol";

/// @title DPO2UL1VerdictReceiver — DPO2U L1 admissions read on another Avalanche chain via ICM
/// @notice Deployed on the C-Chain (or a client L1). Accepts only messages that the
///         TeleporterMessenger delivers from the pinned DPO2U L1 blockchain ID and gate address.
///         Requirement ICM-1 of the SOTA doc. Replaces relayer trust (DPO2UTravelRuleVerdictMirror)
///         with the BLS signature of the DPO2U L1 validator set, checked by the Warp precompile.
/// @dev TRUST MODEL — a message is as good as the DPO2U L1 validator set that signs it (PoA,
///      DPO2U-run in the demo) plus the proof the L1 gate verified. Messages carry a sequence
///      number; older ones are ignored, so a late ADMIT cannot undo a DROP.
contract DPO2UL1VerdictReceiver is ITeleporterReceiver {
    error AdminOnly();
    error NotAuthorized();
    error ZeroAddress();
    error NotTeleporter();
    error UnknownSource();
    error BadKind();

    struct Status {
        uint64 seq;
        uint64 expiresAt; // 0 = not admitted
        bytes32 policyHash;
        bytes32 digest;
    }

    address public immutable teleporter;
    bytes32 public sourceBlockchainId;
    address public sourceGate;
    address public admin;
    address public pendingAdmin;
    mapping(address => Status) private _status;

    event SourceSet(bytes32 blockchainId, address gate);
    event AdmissionMirrored(address indexed subject, uint8 kind, uint64 seq, bytes32 policyHash, bytes32 digest, uint64 expiresAt);
    event StaleMessage(address indexed subject, uint64 seq, uint64 lastSeq);
    event AdminTransferStarted(address indexed from, address indexed to);
    event AdminTransferred(address indexed from, address indexed to);

    modifier onlyAdmin() {
        if (msg.sender != admin) revert AdminOnly();
        _;
    }

    constructor(address teleporter_, bytes32 sourceBlockchainId_, address sourceGate_, address admin_) {
        if (teleporter_ == address(0) || sourceGate_ == address(0) || admin_ == address(0)) revert ZeroAddress();
        teleporter = teleporter_;
        sourceBlockchainId = sourceBlockchainId_;
        sourceGate = sourceGate_;
        admin = admin_;
        emit SourceSet(sourceBlockchainId_, sourceGate_);
    }

    function setSource(bytes32 blockchainId, address gate) external onlyAdmin {
        if (gate == address(0)) revert ZeroAddress();
        sourceBlockchainId = blockchainId;
        sourceGate = gate;
        emit SourceSet(blockchainId, gate);
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        pendingAdmin = newAdmin;
        emit AdminTransferStarted(admin, newAdmin);
    }

    function acceptAdmin() external {
        if (msg.sender != pendingAdmin) revert NotAuthorized();
        emit AdminTransferred(admin, msg.sender);
        admin = msg.sender;
        pendingAdmin = address(0);
    }

    function receiveTeleporterMessage(bytes32 sourceBlockchainID, address originSenderAddress, bytes calldata message) external {
        if (msg.sender != teleporter) revert NotTeleporter();
        if (sourceBlockchainID != sourceBlockchainId || originSenderAddress != sourceGate) revert UnknownSource();
        (uint8 kind, uint64 seq, address subject, bytes32 policyHash, bytes32 digest, uint64 expiresAt) =
            abi.decode(message, (uint8, uint64, address, bytes32, bytes32, uint64));
        if (kind != 1 && kind != 2) revert BadKind();
        Status storage s = _status[subject];
        if (seq <= s.seq) {
            emit StaleMessage(subject, seq, s.seq);
            return;
        }
        s.seq = seq;
        s.expiresAt = kind == 1 ? expiresAt : 0;
        s.policyHash = policyHash;
        s.digest = digest;
        emit AdmissionMirrored(subject, kind, seq, policyHash, digest, s.expiresAt);
    }

    function isAdmitted(address subject) external view returns (bool) {
        return block.timestamp <= _status[subject].expiresAt;
    }

    function statusOf(address subject) external view returns (Status memory) {
        return _status[subject];
    }
}
