// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Groth16 verifier with its verifying key baked in (snarkjs/circom style,
///         one deployment per circuit). The gate never accepts a caller-supplied VK.
interface IGroth16Verifier {
    function verifyProof(
        uint256[2] calldata a,
        uint256[2][2] calldata b,
        uint256[2] calldata c,
        uint256[] calldata pubSignals
    ) external view returns (bool);
}

/// @notice Live association-set provider for the membership lane.
interface IAdmittedRootProvider {
    function currentRoot() external view returns (bytes32);
}

/// @notice Contract that performs the privileged action once the gate allows it
///         (vault rebalance, fee distribution, settlement transfer...).
///         It must only accept calls from the gate.
interface IGatedTarget {
    function onGatedExecution(address operator, bytes32 evidenceHash, bytes calldata payload) external;
}

/// @notice The originator and beneficiary of a Travel Rule transfer, as subject hashes
///         (H(CAIP-10 | DID | registry id)), never identities in clear.
struct TravelParties {
    bytes32 originator;
    bytes32 beneficiary;
}

struct Groth16Proof {
    uint256[2] a;
    uint256[2][2] b;
    uint256[2] c;
}
