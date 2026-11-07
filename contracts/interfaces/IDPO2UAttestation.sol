// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title IDPO2UAttestation — the chain-neutral DPO2U attestation interface (spec v0.1)
/// @notice Same data model the Stellar `anticorruption-attestation` and Midnight
///         `ComplianceRegistry` already use: an attestation is keyed by
///         (useCaseId, evidenceHash), carries a PASS/FAIL/REVIEW verdict and never
///         stores evidence — only hashes. See docs/SPEC.md.
interface IDPO2UAttestation {
    /// NONE = no record. Only PASS can ever make `isValid` true.
    enum Verdict {
        NONE,
        PASS,
        FAIL,
        REVIEW
    }

    /// Who produced the verdict (PSAV spec §6.2). Shown by /verify; never hidden.
    enum Origin {
        MACHINE, // on-chain predicate or ZK proof, reproducible by anyone
        HUMAN_REVIEWED, // evaluator + named reviewer signing the run
        THIRD_PARTY // independent audit/legal opinion referenced and sealed
    }

    struct UseCase {
        bool active;
        bytes32 packHash; // hash of the versioned policy pack (rules + citations)
        uint32 packVersion;
    }

    struct Attestation {
        Verdict verdict;
        Origin origin;
        bool revoked;
        uint64 issuedAt;
        uint64 expiresAt; // mandatory: silence counts as non-compliance
        address submitter;
        bytes32 subject; // H(CAIP-10 account | DID | CNPJ) — never raw identity
        bytes32 metadataHash; // H(run summary: rules, verdicts, reviewers)
        bytes32 packHash;
        uint32 packVersion;
    }

    event UseCaseConfigured(bytes32 indexed useCaseId, bool active, bytes32 packHash, uint32 packVersion);
    event SubmitterAuthorized(address indexed submitter, bool allowed);
    event AttestationRegistered(
        bytes32 indexed useCaseId,
        bytes32 indexed evidenceHash,
        bytes32 indexed subject,
        Verdict verdict,
        Origin origin,
        uint64 expiresAt
    );
    event AttestationRevoked(bytes32 indexed useCaseId, bytes32 indexed evidenceHash, address by, bytes32 reasonHash);

    function registerAttestation(
        bytes32 useCaseId,
        bytes32 evidenceHash,
        bytes32 subject,
        Verdict verdict,
        Origin origin,
        bytes32 metadataHash,
        uint64 expiresAt
    ) external;

    function revokeAttestation(bytes32 useCaseId, bytes32 evidenceHash, bytes32 reasonHash) external;

    function getAttestation(bytes32 useCaseId, bytes32 evidenceHash) external view returns (Attestation memory);

    /// True only for PASS, not revoked, not expired.
    function isValid(bytes32 useCaseId, bytes32 evidenceHash) external view returns (bool);

    /// Oracle entrypoint: is the subject's latest attestation for this use case valid?
    function isSubjectCompliant(bytes32 useCaseId, bytes32 subject) external view returns (bool);
}
