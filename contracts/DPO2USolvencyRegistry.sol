// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "./vendor/sp1/ISP1Verifier.sol";
import {IDPO2UAttestation} from "./interfaces/IDPO2UAttestation.sol";

/// @title DPO2USolvencyRegistry — private proof of reserves on Avalanche
/// @notice C-Chain port of the Midnight `SolvencyRegistry.compact` and the Stellar
///         `seal_solvency` (BCB Res. 519/520/521: client-fund segregation + daily proof
///         of reserve). An SP1 Groth16 proof shows `reserves >= liabilities` without
///         disclosing either amount. Only the verdict, the entity, the off-chain report
///         commitment, the data-source set and an anti-replay context reach the chain.
/// @dev Same rules as DPO2UZkThresholdAttestor:
///      - canonical-VK pinning: verifier and program vkey are immutable, no entrypoint
///        takes a caller-supplied verifier or vkey;
///      - permissionless submission, nothing caller-chosen is written: the evidence hash is
///        sha256(publicValues) and the metadata hash is derived from the vkey and the proof;
///      - an insolvent entity cannot produce a proof with `solvent = true`.
///      The SP1 program is responsible for checking the signatures of the reserve and
///      liability sources; their key set is committed as `sourcesHash` and stored here so
///      anyone can check which custodian/ledger feeds backed the seal.
///      Each seal is also written to the DPO2U registry (MACHINE origin, subject = entityId),
///      so revocation and expiry follow the registry and the PassportOracle can consume it.
///      Public values ABI:
///      (bytes32 entityId, bytes32 reportCommitment, bytes32 context, bytes32 sourcesHash,
///       uint32 period, bool solvent) — 192 bytes.
contract DPO2USolvencyRegistry {
    error BadPublicValues();
    error Insolvent();
    error ZeroEntity();
    error ContextUsed();
    error StalePeriod();

    struct SolvencyRecord {
        uint32 period; // reporting period, YYYYMMDD
        uint64 sealedAt;
        bytes32 reportCommitment; // hash/CID of the off-chain reserve report
        bytes32 context; // H(entity || period || nonce), single use
        bytes32 sourcesHash; // H(signing keys of the reserve and liability feeds)
        bytes32 evidenceHash; // sha256(publicValues), key in the registry
    }

    ISP1Verifier public immutable verifier;
    bytes32 public immutable programVKey;
    IDPO2UAttestation public immutable registry;
    bytes32 public immutable useCaseId;
    /// @notice How long a seal stays valid. A daily PoR regime uses about 1-2 days.
    uint64 public immutable validity;

    mapping(bytes32 => SolvencyRecord) private _latest;
    mapping(bytes32 => bool) public usedContexts;
    uint256 public solvencyCount;

    event SolvencySealed(
        bytes32 indexed entityId,
        bytes32 indexed evidenceHash,
        uint32 period,
        bytes32 reportCommitment,
        bytes32 sourcesHash
    );

    constructor(address verifier_, bytes32 programVKey_, address registry_, bytes32 useCaseId_, uint64 validity_) {
        verifier = ISP1Verifier(verifier_);
        programVKey = programVKey_;
        registry = IDPO2UAttestation(registry_);
        useCaseId = useCaseId_;
        validity = validity_;
    }

    function decodePublicValues(bytes calldata publicValues)
        public
        pure
        returns (
            bytes32 entityId,
            bytes32 reportCommitment,
            bytes32 context,
            bytes32 sourcesHash,
            uint32 period,
            bool solvent
        )
    {
        if (publicValues.length != 192) revert BadPublicValues();
        (entityId, reportCommitment, context, sourcesHash, period, solvent) =
            abi.decode(publicValues, (bytes32, bytes32, bytes32, bytes32, uint32, bool));
    }

    /// @notice Permissionless: anyone holding a valid proof can seal it.
    function sealSolvency(bytes calldata publicValues, bytes calldata proofBytes)
        external
        returns (bytes32 evidenceHash)
    {
        // Reverts on an invalid proof (wrong vkey, tampered bytes or public values).
        verifier.verifyProof(programVKey, publicValues, proofBytes);

        (
            bytes32 entityId,
            bytes32 reportCommitment,
            bytes32 context,
            bytes32 sourcesHash,
            uint32 period,
            bool solvent
        ) = decodePublicValues(publicValues);
        if (!solvent) revert Insolvent();
        if (entityId == bytes32(0)) revert ZeroEntity();
        if (usedContexts[context]) revert ContextUsed();
        // Periods only move forward: an old (possibly solvent) snapshot cannot replace a newer one.
        if (period <= _latest[entityId].period) revert StalePeriod();

        usedContexts[context] = true;
        evidenceHash = sha256(publicValues);
        _latest[entityId] = SolvencyRecord({
            period: period,
            sealedAt: uint64(block.timestamp),
            reportCommitment: reportCommitment,
            context: context,
            sourcesHash: sourcesHash,
            evidenceHash: evidenceHash
        });
        unchecked {
            ++solvencyCount;
        }

        registry.registerAttestation(
            useCaseId,
            evidenceHash,
            entityId,
            IDPO2UAttestation.Verdict.PASS,
            IDPO2UAttestation.Origin.MACHINE,
            keccak256(abi.encode(programVKey, evidenceHash)),
            uint64(block.timestamp) + validity
        );
        emit SolvencySealed(entityId, evidenceHash, period, reportCommitment, sourcesHash);
    }

    /// @notice True while the latest seal of `entityId` is valid in the registry
    ///         (not expired, not revoked, use case active).
    function isSolvent(bytes32 entityId) external view returns (bool) {
        bytes32 e = _latest[entityId].evidenceHash;
        return e != bytes32(0) && registry.isValid(useCaseId, e);
    }

    /// @notice Latest seal of `entityId`. There is no getter for reserves or liabilities:
    ///         both stay private.
    function getSolvencyRecord(bytes32 entityId) external view returns (SolvencyRecord memory) {
        return _latest[entityId];
    }
}
