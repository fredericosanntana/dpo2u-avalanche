// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IDPO2UAttestation} from "./interfaces/IDPO2UAttestation.sol";

/// @title DPO2UComplianceRegistry — DPO2U seal on Avalanche (C-Chain / Fuji)
/// @notice EVM implementation of IDPO2UAttestation. Mirrors the Soroban
///         `anticorruption-attestation` contract (use cases, authorized submitters,
///         one record per (useCaseId, evidenceHash)) and adds the PSAV passport fields:
///         pack hash/version, verdict origin and a mandatory expiry.
/// @dev Invariants (tested):
///      - REVIEW and FAIL are never valid; only PASS can be.
///      - Every attestation expires; an expired or revoked one is not valid.
///      - A (useCaseId, evidenceHash) pair is written once (anti-replay).
///      - Only the admin configures use cases and submitters; admin transfer is two-step.
contract DPO2UComplianceRegistry is IDPO2UAttestation {
    // Error codes mirror the Stellar contract (1..6) so SDKs map them the same way.
    error NotAuthorized(); // 1
    error UseCaseInactive(); // 2
    error AttestationExists(); // 3
    error AttestationNotFound(); // 4
    error AdminOnly(); // 5
    error ZeroAddress();
    error InvalidVerdict();
    error InvalidExpiry();
    error ValidityTooLong();
    error AlreadyRevoked();

    /// Upper bound on validity so a seal cannot be made effectively permanent.
    uint64 public immutable maxValidity;

    address public admin;
    address public pendingAdmin;
    uint256 public attestationCount;

    mapping(bytes32 => UseCase) private _useCases;
    mapping(address => bool) private _submitters;
    mapping(bytes32 => mapping(bytes32 => Attestation)) private _attestations;
    mapping(bytes32 => mapping(bytes32 => bytes32)) private _latestBySubject;

    event AdminTransferStarted(address indexed from, address indexed to);
    event AdminTransferred(address indexed from, address indexed to);

    modifier onlyAdmin() {
        if (msg.sender != admin) revert AdminOnly();
        _;
    }

    constructor(address admin_, uint64 maxValidity_) {
        if (admin_ == address(0)) revert ZeroAddress();
        if (maxValidity_ == 0) revert InvalidExpiry();
        admin = admin_;
        maxValidity = maxValidity_;
    }

    // ── Admin ───────────────────────────────────────────────────────────────

    function configureUseCase(bytes32 useCaseId, bool active, bytes32 packHash, uint32 packVersion)
        external
        onlyAdmin
    {
        _useCases[useCaseId] = UseCase({active: active, packHash: packHash, packVersion: packVersion});
        emit UseCaseConfigured(useCaseId, active, packHash, packVersion);
    }

    function authorizeSubmitter(address submitter, bool allowed) external onlyAdmin {
        if (submitter == address(0)) revert ZeroAddress();
        _submitters[submitter] = allowed;
        emit SubmitterAuthorized(submitter, allowed);
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

    // ── Write ───────────────────────────────────────────────────────────────

    /// @inheritdoc IDPO2UAttestation
    function registerAttestation(
        bytes32 useCaseId,
        bytes32 evidenceHash,
        bytes32 subject,
        Verdict verdict,
        Origin origin,
        bytes32 metadataHash,
        uint64 expiresAt
    ) external {
        if (!_submitters[msg.sender]) revert NotAuthorized();
        UseCase memory uc = _useCases[useCaseId];
        if (!uc.active) revert UseCaseInactive();
        if (verdict == Verdict.NONE) revert InvalidVerdict();
        if (expiresAt <= block.timestamp) revert InvalidExpiry();
        if (expiresAt - block.timestamp > maxValidity) revert ValidityTooLong();

        Attestation storage a = _attestations[useCaseId][evidenceHash];
        if (a.verdict != Verdict.NONE) revert AttestationExists();

        a.verdict = verdict;
        a.origin = origin;
        a.issuedAt = uint64(block.timestamp);
        a.expiresAt = expiresAt;
        a.submitter = msg.sender;
        a.subject = subject;
        a.metadataHash = metadataHash;
        a.packHash = uc.packHash;
        a.packVersion = uc.packVersion;

        _latestBySubject[useCaseId][subject] = evidenceHash;
        unchecked {
            ++attestationCount;
        }
        emit AttestationRegistered(useCaseId, evidenceHash, subject, verdict, origin, expiresAt);
    }

    /// @notice Suspension/revocation stays visible forever (nothing is deleted).
    function revokeAttestation(bytes32 useCaseId, bytes32 evidenceHash, bytes32 reasonHash) external {
        Attestation storage a = _attestations[useCaseId][evidenceHash];
        if (a.verdict == Verdict.NONE) revert AttestationNotFound();
        if (msg.sender != admin && msg.sender != a.submitter) revert NotAuthorized();
        if (a.revoked) revert AlreadyRevoked();
        a.revoked = true;
        emit AttestationRevoked(useCaseId, evidenceHash, msg.sender, reasonHash);
    }

    // ── Read ────────────────────────────────────────────────────────────────

    function getUseCase(bytes32 useCaseId) external view returns (UseCase memory) {
        return _useCases[useCaseId];
    }

    function isSubmitter(address who) external view returns (bool) {
        return _submitters[who];
    }

    /// @inheritdoc IDPO2UAttestation
    function getAttestation(bytes32 useCaseId, bytes32 evidenceHash) external view returns (Attestation memory a) {
        a = _attestations[useCaseId][evidenceHash];
        if (a.verdict == Verdict.NONE) revert AttestationNotFound();
    }

    /// @inheritdoc IDPO2UAttestation
    function isValid(bytes32 useCaseId, bytes32 evidenceHash) public view returns (bool) {
        Attestation storage a = _attestations[useCaseId][evidenceHash];
        return a.verdict == Verdict.PASS && !a.revoked && block.timestamp < a.expiresAt;
    }

    /// @inheritdoc IDPO2UAttestation
    function isSubjectCompliant(bytes32 useCaseId, bytes32 subject) external view returns (bool) {
        bytes32 h = _latestBySubject[useCaseId][subject];
        if (h == bytes32(0)) return false;
        return isValid(useCaseId, h);
    }

    function latestEvidenceOf(bytes32 useCaseId, bytes32 subject) external view returns (bytes32) {
        return _latestBySubject[useCaseId][subject];
    }
}
