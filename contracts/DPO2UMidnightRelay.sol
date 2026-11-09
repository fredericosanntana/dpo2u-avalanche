// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IDPO2UAttestation} from "./interfaces/IDPO2UAttestation.sol";

/// @title DPO2UMidnightRelay — Midnight ComplianceRegistry seals mirrored onto the C-Chain
/// @notice A seal written on Midnight by `attestUseCase(use_case_id, verdict, evidence_hash,
///         metadata_hash)` becomes readable by any C-Chain contract through the DPO2U registry,
///         without trusting a single relayer: `threshold` of the allowlisted relayers must each
///         confirm the exact same seal (same Midnight contract, transaction, use case, verdict,
///         evidence and metadata) before it is registered.
/// @dev - Only Midnight use cases the admin mapped are relayable, each to a C-Chain use case
///        with its own validity (Midnight seals carry no expiry; silence = non-compliance here).
///      - Midnight verdict encoding is 0 = FAIL, 1 = PASS, 2 = REVIEW; it is translated, never
///        widened. Midnight stores no subject, so the subject is H("dpo2u:midnight:", evidence).
///      - metadataHash on the C-Chain = keccak256(Midnight metadata_hash, Midnight contract, tx),
///        so the provenance is part of the sealed record.
///      - A relayer confirms a digest once. Two conflicting digests for the same evidence can
///        collect votes, but only the first to reach the threshold is registered; the registry
///        refuses the second (AttestationExists). A removed relayer's past votes still count
///        toward digests it already confirmed; lower the threshold or rotate before removing
///        if that matters.
///      - This contract must be an authorized submitter in the registry.
contract DPO2UMidnightRelay {
    error AdminOnly();
    error NotAuthorized();
    error NotRelayer();
    error ZeroAddress();
    error ZeroValue();
    error InvalidThreshold();
    error UnmappedUseCase();
    error InvalidVerdict();
    error AlreadyConfirmed();
    error AlreadyRelayed();

    struct MidnightSeal {
        bytes32 midnightContract; // ComplianceRegistry address on Midnight
        bytes32 midnightTx; // transaction id/hash on Midnight
        bytes32 midnightUseCaseId; // use_case_id as stored on Midnight (Bytes<32>)
        uint8 midnightVerdict; // 0 FAIL, 1 PASS, 2 REVIEW
        bytes32 evidenceHash;
        bytes32 metadataHash;
    }

    struct Route {
        bytes32 useCaseId; // C-Chain use case in the registry
        uint64 validity; // seconds a relayed seal stays valid
    }

    IDPO2UAttestation public immutable registry;
    address public admin;
    address public pendingAdmin;
    uint8 public threshold;
    uint8 public relayerCount;
    mapping(address => bool) public isRelayer;
    mapping(bytes32 => Route) public routes; // midnightUseCaseId => C-Chain route

    mapping(bytes32 => uint8) public confirmations; // seal digest => votes
    mapping(bytes32 => mapping(address => bool)) public confirmedBy;
    mapping(bytes32 => bool) public relayed; // seal digest => registered

    event RelayerSet(address indexed relayer, bool allowed);
    event ThresholdSet(uint8 threshold);
    event RouteSet(bytes32 indexed midnightUseCaseId, bytes32 indexed useCaseId, uint64 validity);
    event AdminTransferStarted(address indexed from, address indexed to);
    event AdminTransferred(address indexed from, address indexed to);
    event SealConfirmed(bytes32 indexed digest, address indexed relayer, uint8 confirmations);
    event SealRelayed(
        bytes32 indexed digest,
        bytes32 indexed useCaseId,
        bytes32 indexed evidenceHash,
        bytes32 midnightContract,
        bytes32 midnightTx,
        IDPO2UAttestation.Verdict verdict
    );

    modifier onlyAdmin() {
        if (msg.sender != admin) revert AdminOnly();
        _;
    }

    constructor(address admin_, IDPO2UAttestation registry_, uint8 threshold_) {
        if (admin_ == address(0) || address(registry_) == address(0)) revert ZeroAddress();
        if (threshold_ == 0) revert InvalidThreshold();
        admin = admin_;
        registry = registry_;
        threshold = threshold_;
        emit ThresholdSet(threshold_);
    }

    // ── Admin ───────────────────────────────────────────────────────────────

    function setRelayer(address relayer, bool allowed) external onlyAdmin {
        if (relayer == address(0)) revert ZeroAddress();
        if (isRelayer[relayer] == allowed) return;
        isRelayer[relayer] = allowed;
        if (allowed) ++relayerCount;
        else --relayerCount;
        emit RelayerSet(relayer, allowed);
    }

    /// @notice Threshold may exceed the current relayer count (relaying pauses until enough exist).
    function setThreshold(uint8 threshold_) external onlyAdmin {
        if (threshold_ == 0) revert InvalidThreshold();
        threshold = threshold_;
        emit ThresholdSet(threshold_);
    }

    /// @notice Map a Midnight use case to a C-Chain use case. useCaseId 0 unmaps it.
    function setRoute(bytes32 midnightUseCaseId, bytes32 useCaseId, uint64 validity) external onlyAdmin {
        if (midnightUseCaseId == bytes32(0)) revert ZeroValue();
        if (useCaseId != bytes32(0) && validity == 0) revert ZeroValue();
        routes[midnightUseCaseId] = Route(useCaseId, validity);
        emit RouteSet(midnightUseCaseId, useCaseId, validity);
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

    // ── Relay ───────────────────────────────────────────────────────────────

    function sealDigest(MidnightSeal calldata s) public pure returns (bytes32) {
        return keccak256(abi.encode(keccak256("DPO2U_MIDNIGHT_SEAL_V1"), s));
    }

    function subjectOf(bytes32 evidenceHash) public pure returns (bytes32) {
        return keccak256(abi.encodePacked("dpo2u:midnight:", evidenceHash));
    }

    /// @notice A relayer confirms it observed `s` final on Midnight. The call that reaches the
    ///         threshold registers the seal.
    function confirm(MidnightSeal calldata s) external returns (bool registered) {
        if (!isRelayer[msg.sender]) revert NotRelayer();
        if (s.evidenceHash == bytes32(0) || s.midnightContract == bytes32(0) || s.midnightTx == bytes32(0)) {
            revert ZeroValue();
        }
        if (s.midnightVerdict > 2) revert InvalidVerdict();
        Route memory r = routes[s.midnightUseCaseId];
        if (r.useCaseId == bytes32(0)) revert UnmappedUseCase();

        bytes32 d = sealDigest(s);
        if (relayed[d]) revert AlreadyRelayed();
        if (confirmedBy[d][msg.sender]) revert AlreadyConfirmed();
        confirmedBy[d][msg.sender] = true;
        uint8 votes = ++confirmations[d];
        emit SealConfirmed(d, msg.sender, votes);
        if (votes < threshold) return false;

        relayed[d] = true;
        IDPO2UAttestation.Verdict v = s.midnightVerdict == 1
            ? IDPO2UAttestation.Verdict.PASS
            : s.midnightVerdict == 0 ? IDPO2UAttestation.Verdict.FAIL : IDPO2UAttestation.Verdict.REVIEW;
        registry.registerAttestation(
            r.useCaseId,
            s.evidenceHash,
            subjectOf(s.evidenceHash),
            v,
            IDPO2UAttestation.Origin.MACHINE,
            keccak256(abi.encode(s.metadataHash, s.midnightContract, s.midnightTx)),
            uint64(block.timestamp) + r.validity
        );
        emit SealRelayed(d, r.useCaseId, s.evidenceHash, s.midnightContract, s.midnightTx, v);
        return true;
    }
}
