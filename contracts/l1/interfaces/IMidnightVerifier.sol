// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Verifier of a Midnight (midnight-proofs: Plonk/KZG over BLS12-381, Blake2b transcript)
///         proof against a registered verification key and its public inputs.
/// @dev Implemented as a stateful precompile on the DPO2U L1 (MVE-2) or as a Solidity contract
///      over the EIP-2537 precompiles (MVE-3). Public inputs are elements of the BLS12-381 scalar
///      field, so each fits in a uint256 and must be < r. A test double lives in
///      contracts/l1/test/MockMidnightVerifier.sol.
interface IMidnightVerifier {
    function verify(bytes32 vkHash, bytes calldata proof, uint256[] calldata publicInputs) external view returns (bool);
}
