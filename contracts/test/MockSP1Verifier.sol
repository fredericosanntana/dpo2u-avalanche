// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ISP1Verifier} from "../vendor/sp1/ISP1Verifier.sol";

/// @notice TEST ONLY. Accepts a "proof" equal to keccak256(vkey, publicValues), so tests can
///         exercise contract logic without an SP1 prover. Never deploy outside tests.
contract MockSP1Verifier is ISP1Verifier {
    error InvalidProof();

    function verifyProof(bytes32 programVKey, bytes calldata publicValues, bytes calldata proofBytes)
        external
        pure
    {
        if (keccak256(proofBytes) != keccak256(abi.encode(keccak256(abi.encode(programVKey, publicValues)))))
            revert InvalidProof();
    }
}
