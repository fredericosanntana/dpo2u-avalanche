// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {TravelRuleVerdictV1} from "./libraries/TravelRuleVerdictV1.sol";

/// @notice What a C-Chain contract needs to gate on a mirrored Midnight Travel Rule verdict.
interface ITravelRuleVerdictReader {
    function isPass(bytes32 transferId) external view returns (bool);
    function isReleased(bytes32 transferId) external view returns (bool);
    function requirePass(bytes32 transferId) external view returns (bytes32 digest);
}

/// @title DPO2UTravelRuleVerdictMirror — Midnight TravelRuleGate verdicts mirrored on the C-Chain
/// @notice Receives the public verdict of the Midnight TravelRuleGate in the common format
///         `dpo2u.travel-rule-verdict/1`, recomputes its canonical JSON and SHA-256 digest on-chain
///         (TravelRuleVerdictV1, same digest as Midnight and the Soroban gate in dpo2u-stellar), and
///         records it per transferId once `threshold` distinct allowlisted relayers have confirmed
///         the same digest. Other contracts read it through ITravelRuleVerdictReader.
/// @dev TRUST MODEL — OPERATOR TRUST, NOT A PROOF. There is no Midnight light client or state
///      proof on the C-Chain. The mirror checks the verdict's form (format rules, pinned source
///      gate, allowed policy, digest, M-of-N relayers) but cannot check that Midnight produced it.
///      A dishonest quorum could record a PASS Midnight never produced. Audit: the record keeps the
///      Midnight block and tx; re-exporting the verdict there must give the same digest.
///      - Fail-closed: sources (chain + gate) and policies must be allowed by the admin.
///      - Only anchored verdicts (block + tx) are accepted.
///      - A FAIL is final. A PASS not released can later become the same PASS released (the
///        VASP released it on Midnight), with the same roots, policy, source and sanctions.
///      - A relayer that is removed stops counting: confirmations are re-counted against the
///        current allowlist when the threshold is checked.
contract DPO2UTravelRuleVerdictMirror is ITravelRuleVerdictReader {
    using TravelRuleVerdictV1 for TravelRuleVerdictV1.Verdict;

    error AdminOnly();
    error NotAuthorized();
    error NotRelayer();
    error ZeroAddress();
    error InvalidThreshold();
    error Unanchored();
    error SourceNotPinned();
    error PolicyNotAllowed();
    error ZeroPolicy();
    error AlreadyRecorded();
    error Conflict();
    error AlreadyConfirmed();
    error NotCleared();

    struct Record {
        bytes32 digest;
        bool pass;
        bool released;
        uint8 reasonCode;
        bytes32 stableHash; // every field except `released` and the anchor
        uint64 sourceBlock; // Midnight block height of the anchoring tx
        bytes sourceTx; // Midnight tx id
        uint64 recordedAt;
        address[] relayedBy;
    }

    address public admin;
    address public pendingAdmin;
    uint8 public threshold;
    uint16 public relayerCount;
    mapping(address => bool) public isRelayer;
    mapping(bytes32 => bool) public sourceAllowed; // sourceKey(chain, contract) => allowed
    mapping(bytes32 => bool) public policyAllowed;

    mapping(bytes32 => address[]) private _pending; // digest => relayers that confirmed it
    mapping(bytes32 => Record) private _records; // transferId => record

    event RelayerSet(address indexed relayer, bool allowed);
    event ThresholdSet(uint8 threshold);
    event SourceSet(bytes32 indexed sourceKey, string sourceChain, bytes sourceContract, bool allowed);
    event PolicySet(bytes32 indexed policyHash, bool allowed);
    event AdminTransferStarted(address indexed from, address indexed to);
    event AdminTransferred(address indexed from, address indexed to);
    event VerdictConfirmed(bytes32 indexed transferId, bytes32 indexed digest, address indexed relayer, uint256 confirmations);
    event VerdictRecorded(bytes32 indexed transferId, bytes32 indexed digest, bool pass, bool released, uint8 reasonCode);

    modifier onlyAdmin() {
        if (msg.sender != admin) revert AdminOnly();
        _;
    }

    constructor(address admin_, uint8 threshold_) {
        if (admin_ == address(0)) revert ZeroAddress();
        if (threshold_ == 0) revert InvalidThreshold();
        admin = admin_;
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

    function setThreshold(uint8 threshold_) external onlyAdmin {
        if (threshold_ == 0) revert InvalidThreshold();
        threshold = threshold_;
        emit ThresholdSet(threshold_);
    }

    /// @notice Pin a source gate, e.g. ("midnight:preview", <TravelRuleGate address>).
    function setSource(string calldata sourceChain, bytes calldata sourceContract, bool allowed) external onlyAdmin {
        bytes32 k = sourceKey(sourceChain, sourceContract);
        sourceAllowed[k] = allowed;
        emit SourceSet(k, sourceChain, sourceContract, allowed);
    }

    function setPolicy(bytes32 policyHash, bool allowed) external onlyAdmin {
        policyAllowed[policyHash] = allowed;
        emit PolicySet(policyHash, allowed);
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

    function sourceKey(string memory sourceChain, bytes memory sourceContract) public pure returns (bytes32) {
        return keccak256(abi.encode(sourceChain, sourceContract));
    }

    /// @notice sha256 of the canonical JSON (reverts if the verdict breaks the format rules).
    function digest(TravelRuleVerdictV1.Verdict calldata v) external pure returns (bytes32) {
        return v.digest();
    }

    function canonical(TravelRuleVerdictV1.Verdict calldata v) external pure returns (bytes memory) {
        return v.canonical();
    }

    /// @notice A relayer confirms a verdict it read on the source chain. Returns the number of
    ///         confirmations of this exact digest from current relayers; at `threshold` it is recorded.
    function submit(TravelRuleVerdictV1.Verdict calldata v) external returns (uint256 confirmations) {
        if (!isRelayer[msg.sender]) revert NotRelayer();
        if (!v.anchored) revert Unanchored();
        if (v.policyHash == bytes32(0)) revert ZeroPolicy();
        if (!sourceAllowed[sourceKey(v.sourceChain, v.sourceContract)]) revert SourceNotPinned();
        if (!policyAllowed[v.policyHash]) revert PolicyNotAllowed();
        bytes32 d = TravelRuleVerdictV1.digest(v); // also enforces the format rules
        bytes32 stable = _stableHash(v);

        Record storage prev = _records[v.transferId];
        if (prev.digest != bytes32(0)) {
            if (prev.digest == d) revert AlreadyRecorded();
            bool isRelease = prev.pass && !prev.released && v.pass && v.released && prev.stableHash == stable;
            if (!isRelease) revert Conflict();
        }

        address[] storage pending = _pending[d];
        for (uint256 i = 0; i < pending.length; i++) {
            if (pending[i] == msg.sender) revert AlreadyConfirmed();
        }
        pending.push(msg.sender);
        address[] memory valid = _valid(pending);
        confirmations = valid.length;
        emit VerdictConfirmed(v.transferId, d, msg.sender, confirmations);
        if (confirmations < threshold) return confirmations;

        Record storage r = _records[v.transferId];
        r.digest = d;
        r.pass = v.pass;
        r.released = v.released;
        r.reasonCode = v.reasonCode;
        r.stableHash = stable;
        r.sourceBlock = v.anchor.height;
        r.sourceTx = v.anchor.tx;
        r.recordedAt = uint64(block.timestamp);
        r.relayedBy = valid;
        delete _pending[d];
        emit VerdictRecorded(v.transferId, d, v.pass, v.released, v.reasonCode);
    }

    // ── Read ────────────────────────────────────────────────────────────────

    function getRecord(bytes32 transferId) external view returns (Record memory) {
        return _records[transferId];
    }

    function pendingConfirmations(bytes32 digest_) external view returns (address[] memory) {
        return _pending[digest_];
    }

    function isPass(bytes32 transferId) external view returns (bool) {
        return _records[transferId].pass;
    }

    function isReleased(bytes32 transferId) external view returns (bool) {
        return _records[transferId].released;
    }

    function requirePass(bytes32 transferId) external view returns (bytes32) {
        Record storage r = _records[transferId];
        if (!r.pass) revert NotCleared();
        return r.digest;
    }

    // ── Internal ────────────────────────────────────────────────────────────

    function _valid(address[] storage pending) private view returns (address[] memory out) {
        uint256 n;
        for (uint256 i = 0; i < pending.length; i++) if (isRelayer[pending[i]]) n++;
        out = new address[](n);
        n = 0;
        for (uint256 i = 0; i < pending.length; i++) if (isRelayer[pending[i]]) out[n++] = pending[i];
    }

    function _stableHash(TravelRuleVerdictV1.Verdict calldata v) private pure returns (bytes32) {
        return keccak256(
            abi.encode(
                v.transferId,
                v.pass,
                v.reasonCode,
                v.policyHash,
                v.originatorRoot,
                v.beneficiaryRoot,
                keccak256(abi.encode(v.sourceChain, v.sourceContract)),
                v.hasSanctions,
                v.sanctions
            )
        );
    }
}
