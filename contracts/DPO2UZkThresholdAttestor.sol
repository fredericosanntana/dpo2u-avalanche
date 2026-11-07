// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "./vendor/sp1/ISP1Verifier.sol";
import {IDPO2UAttestation} from "./interfaces/IDPO2UAttestation.sol";

/// @title DPO2UZkThresholdAttestor — score-private seal on Avalanche
/// @notice Verifies the DPO2U SP1 v6 Groth16 proof of `score >= threshold` (the same
///         proof already verified on Solana) and, on success, writes a MACHINE-origin
///         PASS into the registry. The score never touches the chain.
/// @dev Canonical-VK pinning (Stellar T1 fix, "solved by construction" on Midnight):
///      the SP1 verifier address and the program vkey are immutable. No entrypoint
///      accepts a caller-supplied verifier or vkey. The evidence hash is derived
///      on-chain as sha256(publicValues), so a proof can be sealed only once.
///      Public values ABI: (uint32 threshold, bytes32 subjectCommitment, bool meetsThreshold).
contract DPO2UZkThresholdAttestor {
    error BelowMinimumThreshold();
    error ThresholdNotMet();
    error BadPublicValues();

    ISP1Verifier public immutable verifier;
    bytes32 public immutable programVKey;
    IDPO2UAttestation public immutable registry;
    bytes32 public immutable useCaseId;
    uint32 public immutable minThreshold;
    uint64 public immutable validity;

    event ProofSealed(bytes32 indexed evidenceHash, bytes32 indexed subject, uint32 threshold);

    constructor(
        address verifier_,
        bytes32 programVKey_,
        address registry_,
        bytes32 useCaseId_,
        uint32 minThreshold_,
        uint64 validity_
    ) {
        verifier = ISP1Verifier(verifier_);
        programVKey = programVKey_;
        registry = IDPO2UAttestation(registry_);
        useCaseId = useCaseId_;
        minThreshold = minThreshold_;
        validity = validity_;
    }

    function decodePublicValues(bytes calldata publicValues)
        public
        pure
        returns (uint32 threshold, bytes32 subject, bool meets)
    {
        if (publicValues.length != 96) revert BadPublicValues();
        (threshold, subject, meets) = abi.decode(publicValues, (uint32, bytes32, bool));
    }

    /// @notice Permissionless: anyone holding a valid proof can seal it.
    function submitProof(bytes calldata publicValues, bytes calldata proofBytes, bytes32 metadataHash)
        external
        returns (bytes32 evidenceHash)
    {
        // Reverts on an invalid proof (wrong vkey, tampered bytes or public values).
        verifier.verifyProof(programVKey, publicValues, proofBytes);

        (uint32 threshold, bytes32 subject, bool meets) = decodePublicValues(publicValues);
        if (!meets) revert ThresholdNotMet();
        if (threshold < minThreshold) revert BelowMinimumThreshold();

        evidenceHash = sha256(publicValues);
        registry.registerAttestation(
            useCaseId,
            evidenceHash,
            subject,
            IDPO2UAttestation.Verdict.PASS,
            IDPO2UAttestation.Origin.MACHINE,
            metadataHash,
            uint64(block.timestamp) + validity
        );
        emit ProofSealed(evidenceHash, subject, threshold);
    }
}
