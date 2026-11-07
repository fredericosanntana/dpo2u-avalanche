// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IDPO2UAttestation} from "./interfaces/IDPO2UAttestation.sol";
import {
    IGroth16Verifier,
    IAdmittedRootProvider,
    IGatedTarget,
    TravelParties,
    Groth16Proof
} from "./interfaces/ITravelRuleGate.sol";

/// @title DPO2UTravelRuleGate — operator-side action gated by a DPO2U verdict
/// @notice Solidity port of the Soroban `defindex-rebalance-gate` (dpo2u-stellar,
///         branch feat/por-ceremony), framed as the Travel Rule adjacent circuit of
///         docs/PHASE2-TRAVEL-RULE-ADJACENT-FLOW.md: a privileged action only goes
///         through when the off-chain Travel Rule / screening artifact got a PASS.
///
///         Every execution requires, in this order:
///           1. operator: msg.sender is an authorized operator;
///           2. validity: block.timestamp <= expiresAt of the intent;
///           3. anti-replay: the evidence hash was never consumed;
///           4. binding: evidenceHash == deriveEvidenceHash(intent), so the verdict
///              covers exactly this payload, target, chain and gate;
///           5. parties (optional): originator and beneficiary are compliant in the
///              registry under `partyUseCaseId`;
///           6. PASS, through one of two lanes:
///              - attestation lane: the registry holds a valid PASS for
///                (useCaseId, evidenceHash) — not FAIL/REVIEW, not revoked, not expired;
///              - proof lane: a Groth16 proof bound to the intent by a context signal.
///
/// @dev Differences from the Soroban gate, all deliberate:
///      - Verifiers are immutable (SPEC invariant 6) instead of admin-settable with a
///        caller-stored VK. One verifier per lane, since EVM Groth16 verifiers embed
///        their VK. A zero address disables that lane.
///      - Nullifiers live in their own set instead of sharing the evidence set.
///      - The attestation lane also enforces registry expiry/revocation (`isValid`),
///        not only the verdict.
///      - Hashes use keccak256(abi.encode(...)) instead of sha256(XDR).
contract DPO2UTravelRuleGate {
    // Numbering follows the Soroban GateError so SDKs map them the same way.
    error Unauthorized(); // 1
    error AttestationMissing(); // 2
    error AttestationNotPass(); // 3
    error EvidenceHashMismatch(); // 4
    error EvidenceExpired(); // 5
    error EvidenceReplay(); // 6
    error VerifierNotSet(); // 7
    error ZkVerifyFailed(); // 8
    error BadProofSignals(); // 9
    error BadProofContext(); // 10
    error ProofNotPass(); // 11
    error NonMemberRoot(); // 12
    error NullifierReplay(); // 13
    error AdmittedRootNotSet(); // 14
    // EVM-only
    error AttestationNotValid(); // PASS but revoked or expired in the registry
    error PartyNotCompliant();
    error AdminOnly();
    error ZeroAddress();
    error Reentrancy();

    bytes32 public constant EVIDENCE_TAG = keccak256("dpo2u.travel-rule-gate.evidence.v1");
    bytes32 public constant ZK_CONTEXT_TAG = keccak256("dpo2u.travel-rule-gate.zkctx.v1");
    uint256 private constant FIELD_MASK = (uint256(1) << 248) - 1; // context fits the BN254 field

    IDPO2UAttestation public immutable registry;
    /// 3 public signals: [pass, commit, context]
    IGroth16Verifier public immutable policyVerifier;
    /// 4 public signals: [root, nullifier, recipient, context]
    IGroth16Verifier public immutable membershipVerifier;

    address public admin;
    address public pendingAdmin;
    address public target;
    bytes32 public useCaseId;
    /// Use case under which originator/beneficiary must be compliant. Zero = not checked.
    bytes32 public partyUseCaseId;
    bytes32 public admittedRoot;
    address public rootProvider;

    mapping(address => bool) public isOperator;
    mapping(bytes32 => bool) public consumedEvidence;
    mapping(bytes32 => bool) public consumedNullifier;

    uint256 private _lock = 1;

    event OperatorAuthorized(address indexed operator, bool allowed);
    event TargetSet(address indexed target);
    event UseCaseSet(bytes32 indexed useCaseId, bytes32 indexed partyUseCaseId);
    event AdmittedRootSet(bytes32 root);
    event RootProviderSet(address indexed provider);
    event AdminTransferStarted(address indexed from, address indexed to);
    event AdminTransferred(address indexed from, address indexed to);
    /// authMode: "attest" or "zk". zkContext is zero on the attestation lane.
    event GatedExecution(
        address indexed operator,
        bytes32 indexed evidenceHash,
        address indexed target,
        bytes32 useCaseId,
        bytes32 authMode,
        bytes32 scope,
        uint64 nonce,
        uint64 expiresAt,
        bytes32 zkContext,
        bytes32 payloadHash
    );

    modifier onlyAdmin() {
        if (msg.sender != admin) revert AdminOnly();
        _;
    }

    modifier nonReentrant() {
        if (_lock != 1) revert Reentrancy();
        _lock = 2;
        _;
        _lock = 1;
    }

    constructor(
        address admin_,
        IDPO2UAttestation registry_,
        address target_,
        bytes32 useCaseId_,
        bytes32 partyUseCaseId_,
        IGroth16Verifier policyVerifier_,
        IGroth16Verifier membershipVerifier_
    ) {
        if (admin_ == address(0) || address(registry_) == address(0) || target_ == address(0)) revert ZeroAddress();
        admin = admin_;
        registry = registry_;
        target = target_;
        useCaseId = useCaseId_;
        partyUseCaseId = partyUseCaseId_;
        policyVerifier = policyVerifier_;
        membershipVerifier = membershipVerifier_;
    }

    // ── Admin ───────────────────────────────────────────────────────────────

    function authorizeOperator(address operator, bool allowed) external onlyAdmin {
        isOperator[operator] = allowed;
        emit OperatorAuthorized(operator, allowed);
    }

    function setTarget(address target_) external onlyAdmin {
        if (target_ == address(0)) revert ZeroAddress();
        target = target_;
        emit TargetSet(target_);
    }

    function setUseCases(bytes32 useCaseId_, bytes32 partyUseCaseId_) external onlyAdmin {
        useCaseId = useCaseId_;
        partyUseCaseId = partyUseCaseId_;
        emit UseCaseSet(useCaseId_, partyUseCaseId_);
    }

    /// Pin the admitted positive-set root for the membership lane (demo / pin-first path).
    function setAdmittedRoot(bytes32 root) external onlyAdmin {
        admittedRoot = root;
        emit AdmittedRootSet(root);
    }

    /// Point the membership lane at a live provider; address(0) falls back to the pinned root.
    function setRootProvider(address provider) external onlyAdmin {
        rootProvider = provider;
        emit RootProviderSet(provider);
    }

    function transferAdmin(address newAdmin) external onlyAdmin {
        if (newAdmin == address(0)) revert ZeroAddress();
        pendingAdmin = newAdmin;
        emit AdminTransferStarted(admin, newAdmin);
    }

    function acceptAdmin() external {
        if (msg.sender != pendingAdmin) revert AdminOnly();
        emit AdminTransferred(admin, msg.sender);
        admin = msg.sender;
        pendingAdmin = address(0);
    }

    // ── Derivations (the control plane computes the same values off-chain) ──

    /// The hash the DPO2U verdict must be sealed under. Binds chain, gate, target,
    /// use case, scope, nonce, expiry, operator, parties and the exact payload.
    function deriveEvidenceHash(
        address operator,
        bytes32 scope,
        uint64 nonce,
        uint64 expiresAt,
        TravelParties calldata parties,
        bytes calldata payload
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                EVIDENCE_TAG,
                block.chainid,
                address(this),
                target,
                useCaseId,
                scope,
                nonce,
                expiresAt,
                operator,
                parties.originator,
                parties.beneficiary,
                keccak256(payload)
            )
        );
    }

    /// Context public signal a proof must carry to be bound to this intent.
    function deriveZkContext(bytes32 evidenceHash) public pure returns (uint256) {
        return uint256(keccak256(abi.encode(ZK_CONTEXT_TAG, evidenceHash))) & FIELD_MASK;
    }

    function resolveAdmittedRoot() public view returns (bytes32) {
        if (rootProvider != address(0)) return IAdmittedRootProvider(rootProvider).currentRoot();
        if (admittedRoot == bytes32(0)) revert AdmittedRootNotSet();
        return admittedRoot;
    }

    // ── Execution ───────────────────────────────────────────────────────────

    /// Attestation lane: the registry must hold a valid PASS for the evidence hash.
    function execute(
        bytes32 scope,
        uint64 nonce,
        uint64 expiresAt,
        bytes32 evidenceHash,
        TravelParties calldata parties,
        bytes calldata payload
    ) external nonReentrant {
        _validateCommon(scope, nonce, expiresAt, evidenceHash, parties, payload);

        bytes32 uc = useCaseId;
        IDPO2UAttestation.Attestation memory a;
        try registry.getAttestation(uc, evidenceHash) returns (IDPO2UAttestation.Attestation memory got) {
            a = got;
        } catch {
            revert AttestationMissing();
        }
        if (a.verdict != IDPO2UAttestation.Verdict.PASS) revert AttestationNotPass();
        if (!registry.isValid(uc, evidenceHash)) revert AttestationNotValid();

        _forward(scope, nonce, expiresAt, evidenceHash, payload, "attest", bytes32(0));
    }

    /// Proof lane. The lane is picked by the public signal count:
    ///   3 → policy circuit      [pass, commit, context]
    ///   4 → membership circuit  [root, nullifier, recipient, context]
    function executeWithProof(
        bytes32 scope,
        uint64 nonce,
        uint64 expiresAt,
        bytes32 evidenceHash,
        TravelParties calldata parties,
        bytes calldata payload,
        Groth16Proof calldata proof,
        uint256[] calldata pubSignals
    ) external nonReentrant {
        _validateCommon(scope, nonce, expiresAt, evidenceHash, parties, payload);

        uint256 expectedContext = deriveZkContext(evidenceHash);
        IGroth16Verifier verifier;
        bytes32 nullifier;

        if (pubSignals.length == 3) {
            if (pubSignals[0] != 1) revert ProofNotPass();
            if (pubSignals[2] != expectedContext) revert BadProofContext();
            verifier = policyVerifier;
        } else if (pubSignals.length == 4) {
            if (bytes32(pubSignals[0]) != resolveAdmittedRoot()) revert NonMemberRoot();
            nullifier = bytes32(pubSignals[1]);
            if (consumedNullifier[nullifier]) revert NullifierReplay();
            if (pubSignals[3] != expectedContext) revert BadProofContext();
            verifier = membershipVerifier;
        } else {
            revert BadProofSignals();
        }

        if (address(verifier) == address(0)) revert VerifierNotSet();
        if (!verifier.verifyProof(proof.a, proof.b, proof.c, pubSignals)) revert ZkVerifyFailed();

        // Burn the nullifier only after the proof verifies, so a failed verify
        // cannot grief-lock someone else's nullifier.
        if (pubSignals.length == 4) consumedNullifier[nullifier] = true;

        _forward(scope, nonce, expiresAt, evidenceHash, payload, "zk", bytes32(expectedContext));
    }

    function _validateCommon(
        bytes32 scope,
        uint64 nonce,
        uint64 expiresAt,
        bytes32 evidenceHash,
        TravelParties calldata parties,
        bytes calldata payload
    ) private view {
        if (!isOperator[msg.sender]) revert Unauthorized();
        if (block.timestamp > expiresAt) revert EvidenceExpired();
        if (consumedEvidence[evidenceHash]) revert EvidenceReplay();
        if (evidenceHash != deriveEvidenceHash(msg.sender, scope, nonce, expiresAt, parties, payload)) {
            revert EvidenceHashMismatch();
        }
        bytes32 puc = partyUseCaseId;
        if (puc != bytes32(0)) {
            if (!registry.isSubjectCompliant(puc, parties.originator)) revert PartyNotCompliant();
            if (!registry.isSubjectCompliant(puc, parties.beneficiary)) revert PartyNotCompliant();
        }
    }

    function _forward(
        bytes32 scope,
        uint64 nonce,
        uint64 expiresAt,
        bytes32 evidenceHash,
        bytes calldata payload,
        bytes32 authMode,
        bytes32 zkContext
    ) private {
        consumedEvidence[evidenceHash] = true; // before the external call
        address t = target;
        IGatedTarget(t).onGatedExecution(msg.sender, evidenceHash, payload);
        emit GatedExecution(
            msg.sender, evidenceHash, t, useCaseId, authMode, scope, nonce, expiresAt, zkContext, keccak256(payload)
        );
    }
}
