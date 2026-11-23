// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IAllowList} from "./interfaces/IAllowList.sol";
import {IMidnightVerifier} from "./interfaces/IMidnightVerifier.sol";
import {ITeleporterMessenger, TeleporterMessageInput, TeleporterFeeInfo} from "./interfaces/ITeleporter.sol";

/// @title DPO2UL1ComplianceGate — admission to the DPO2U L1 by Midnight proof
/// @notice Runs on the DPO2U Avalanche L1 (Subnet-EVM) and holds the Manager role of the
///         Transaction AllowList precompile. A wallet can send transactions on the L1 only while
///         it holds an admission: a Midnight TravelRuleGate PASS, proven (not relayed) and bound
///         to that wallet, this chain and this gate. Requirements GE-1..GE-5 of the SOTA doc.
/// @dev TRUST MODEL — the proof is checked by `verifier` (the MidnightVerifier precompile or an
///      EIP-2537 contract). Not proven: that the Midnight tx was included in the Midnight ledger
///      (no light client). The pins below (VK hash, sanctions root, min issued_at, policy hash)
///      are what make a proof made with another circuit, list or policy fail here.
///
///      PUBLIC INPUT LAYOUT v0 (PROVISIONAL): fixed until phase A3 maps it to the real
///      `evaluateTransfer` statement. 32-byte values travel as two 128-bit limbs (hi, lo) because
///      every public input must be a BLS12-381 scalar (< r).
///        0 pass (1 = PASS)          7 issued_at (list snapshot, unix s)   12 nonce
///        1-2 policy_hash            8 valid_until (list, unix s)          13-14 verdict digest
///        3-4 sanctions list_root    9 subject (wallet address)            (dpo2u.travel-rule-verdict/1)
///        5-6 provider_id            10 chain id   11 gate address
///
///      DATA PROTECTION (LGPD): nothing here identifies a person. The subject is a wallet; the
///      wallet <-> person link stays with the VASP. Events and ICM messages carry only the wallet,
///      policy hash, verdict digest and expiry.
contract DPO2UL1ComplianceGate {
    // ── Errors ──────────────────────────────────────────────────────────────
    error AdminOnly();
    error NotAuthorized();
    error ZeroAddress();
    error BadPublicInputs();
    error NotPass();
    error PolicyNotActive();
    error InvalidProof();
    error ProviderNotPinned();
    error WrongListRoot();
    error StaleList();
    error ListExpired();
    error WrongChain();
    error WrongGate();
    error NonceUsed();
    error SubjectFrozen();
    error NotExpired();
    error NotAdmitted();
    error BadTtl();

    // ── Layout v0 ───────────────────────────────────────────────────────────
    uint256 public constant PI_PASS = 0;
    uint256 public constant PI_POLICY = 1; // + 2
    uint256 public constant PI_ROOT = 3; // + 4
    uint256 public constant PI_PROVIDER = 5; // + 6
    uint256 public constant PI_ISSUED_AT = 7;
    uint256 public constant PI_VALID_UNTIL = 8;
    uint256 public constant PI_SUBJECT = 9;
    uint256 public constant PI_CHAIN_ID = 10;
    uint256 public constant PI_GATE = 11;
    uint256 public constant PI_NONCE = 12;
    uint256 public constant PI_DIGEST = 13; // + 14
    uint256 public constant PI_COUNT = 15;

    uint256 internal constant ROLE_NONE = 0;
    uint256 internal constant ROLE_ENABLED = 1;

    /// @notice ICM message kinds sent to the registered destinations.
    uint8 public constant MSG_ADMIT = 1;
    uint8 public constant MSG_DROP = 2;

    // ── State ───────────────────────────────────────────────────────────────
    struct Policy {
        bytes32 vkHash; // hash of the Midnight verification key of the circuit that proves it
        uint64 admissionTtl; // max seconds an admission lasts (also capped by the list's valid_until)
        bool active;
    }

    struct ProviderPin {
        bytes32 listRoot; // the only sanctions root accepted from this provider
        uint64 minIssuedAt; // snapshots issued before this are refused (stale-list fix)
        bool active;
    }

    struct Admission {
        uint64 expiresAt;
        bool granted; // this gate set the Enabled role (so it is the one to remove it)
        bytes32 policyHash;
        bytes32 digest;
    }

    struct Destination {
        bytes32 blockchainId;
        address receiver;
        uint256 gasLimit;
    }

    IAllowList public immutable txAllowList;
    IMidnightVerifier public immutable verifier;

    address public admin;
    address public pendingAdmin;
    ITeleporterMessenger public teleporter; // zero = no ICM
    uint64 public seq; // ICM message sequence, so receivers can drop out-of-order messages

    mapping(bytes32 => Policy) public policies;
    mapping(bytes32 => ProviderPin) public providers;
    mapping(address => Admission) private _admissions;
    mapping(address => bool) public frozen;
    mapping(bytes32 => bool) public nonceUsed; // keccak(subject, nonce)
    Destination[] private _destinations;

    // ── Events ──────────────────────────────────────────────────────────────
    event PolicySet(bytes32 indexed policyHash, bytes32 vkHash, uint64 admissionTtl, bool active);
    event ProviderSet(bytes32 indexed providerId, bytes32 listRoot, uint64 minIssuedAt, bool active);
    event Admitted(address indexed subject, bytes32 indexed policyHash, bytes32 digest, uint64 expiresAt, bool granted);
    event Dropped(address indexed subject, uint8 indexed cause, bytes32 reasonHash); // cause: 1 expired, 2 revoked
    event FrozenSet(address indexed subject, bool frozen, bytes32 reasonHash);
    event TeleporterSet(address teleporter);
    event DestinationAdded(bytes32 indexed blockchainId, address receiver, uint256 gasLimit);
    event DestinationsCleared();
    event IcmSent(bytes32 indexed messageId, uint64 seq, uint8 kind, address indexed subject);
    event AdminTransferStarted(address indexed from, address indexed to);
    event AdminTransferred(address indexed from, address indexed to);

    modifier onlyAdmin() {
        if (msg.sender != admin) revert AdminOnly();
        _;
    }

    /// @param txAllowList_ 0x0200000000000000000000000000000000000002 on the L1 (a mock in tests)
    /// @param verifier_ the MidnightVerifier precompile or contract
    /// @param admin_ the L1 Safe 2-of-3
    constructor(address txAllowList_, address verifier_, address admin_) {
        if (txAllowList_ == address(0) || verifier_ == address(0) || admin_ == address(0)) revert ZeroAddress();
        txAllowList = IAllowList(txAllowList_);
        verifier = IMidnightVerifier(verifier_);
        admin = admin_;
    }

    // ── Admin (GE-1) ────────────────────────────────────────────────────────

    function setPolicy(bytes32 policyHash, bytes32 vkHash, uint64 admissionTtl, bool active) external onlyAdmin {
        if (active && (vkHash == bytes32(0) || admissionTtl == 0)) revert BadTtl();
        policies[policyHash] = Policy(vkHash, admissionTtl, active);
        emit PolicySet(policyHash, vkHash, admissionTtl, active);
    }

    function setProvider(bytes32 providerId, bytes32 listRoot, uint64 minIssuedAt, bool active) external onlyAdmin {
        providers[providerId] = ProviderPin(listRoot, minIssuedAt, active);
        emit ProviderSet(providerId, listRoot, minIssuedAt, active);
    }

    /// @notice Sanctions freeze: drops the admission now and refuses new ones until unfrozen.
    function setFrozen(address subject, bool isFrozen, bytes32 reasonHash) external onlyAdmin {
        frozen[subject] = isFrozen;
        emit FrozenSet(subject, isFrozen, reasonHash);
        if (isFrozen && _admissions[subject].expiresAt != 0) _drop(subject, 2, reasonHash);
    }

    /// @notice GE-3: immediate revocation by the Safe.
    function revoke(address subject, bytes32 reasonHash) external onlyAdmin {
        if (_admissions[subject].expiresAt == 0) revert NotAdmitted();
        _drop(subject, 2, reasonHash);
    }

    function setTeleporter(address teleporter_) external onlyAdmin {
        teleporter = ITeleporterMessenger(teleporter_);
        emit TeleporterSet(teleporter_);
    }

    function addDestination(bytes32 blockchainId, address receiver, uint256 gasLimit) external onlyAdmin {
        if (receiver == address(0)) revert ZeroAddress();
        _destinations.push(Destination(blockchainId, receiver, gasLimit));
        emit DestinationAdded(blockchainId, receiver, gasLimit);
    }

    function clearDestinations() external onlyAdmin {
        delete _destinations;
        emit DestinationsCleared();
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

    // ── Admission (GE-2) ────────────────────────────────────────────────────

    /// @notice Anyone may submit (the relayer only transports): the proof decides.
    function admit(bytes calldata proof, uint256[] calldata pi) external returns (address subject) {
        if (pi.length != PI_COUNT) revert BadPublicInputs();
        if (pi[PI_PASS] != 1) revert NotPass();

        bytes32 policyHash = _join(pi, PI_POLICY);
        Policy memory p = policies[policyHash];
        if (!p.active) revert PolicyNotActive();
        if (!verifier.verify(p.vkHash, proof, pi)) revert InvalidProof();

        ProviderPin memory pin = providers[_join(pi, PI_PROVIDER)];
        if (!pin.active) revert ProviderNotPinned();
        if (_join(pi, PI_ROOT) != pin.listRoot) revert WrongListRoot();
        uint64 issuedAt = _u64(pi[PI_ISSUED_AT]);
        uint64 validUntil = _u64(pi[PI_VALID_UNTIL]);
        if (issuedAt < pin.minIssuedAt) revert StaleList();
        if (block.timestamp > validUntil) revert ListExpired();

        if (pi[PI_CHAIN_ID] != block.chainid) revert WrongChain();
        if (pi[PI_GATE] != uint256(uint160(address(this)))) revert WrongGate();
        if (pi[PI_SUBJECT] == 0 || pi[PI_SUBJECT] >> 160 != 0) revert BadPublicInputs();
        subject = address(uint160(pi[PI_SUBJECT]));
        if (frozen[subject]) revert SubjectFrozen();

        bytes32 nk = keccak256(abi.encode(subject, pi[PI_NONCE]));
        if (nonceUsed[nk]) revert NonceUsed();
        nonceUsed[nk] = true;

        uint64 expiresAt = uint64(block.timestamp) + p.admissionTtl;
        if (expiresAt > validUntil) expiresAt = validUntil;

        // Effects before the precompile call and the ICM send.
        Admission storage a = _admissions[subject];
        bool granted = a.granted;
        a.expiresAt = expiresAt;
        a.policyHash = policyHash;
        a.digest = _join(pi, PI_DIGEST);

        // Only touch wallets with no role: never downgrade or claim an Admin/Manager, and leave
        // alone a wallet the Safe enabled directly.
        if (!granted && txAllowList.readAllowList(subject) == ROLE_NONE) {
            a.granted = true;
            granted = true;
            txAllowList.setEnabled(subject);
        }
        emit Admitted(subject, policyHash, a.digest, expiresAt, granted);
        _broadcast(MSG_ADMIT, subject, policyHash, a.digest, expiresAt);
    }

    /// @notice GE-3: anyone may remove an admission once it has expired (watcher job).
    function expire(address subject) external {
        Admission memory a = _admissions[subject];
        if (a.expiresAt == 0) revert NotAdmitted();
        if (block.timestamp <= a.expiresAt) revert NotExpired();
        _drop(subject, 1, bytes32(0));
    }

    // ── Views ───────────────────────────────────────────────────────────────

    function isAdmitted(address subject) public view returns (bool) {
        return !frozen[subject] && block.timestamp <= _admissions[subject].expiresAt;
    }

    function admissionOf(address subject) external view returns (Admission memory) {
        return _admissions[subject];
    }

    function destinations() external view returns (Destination[] memory) {
        return _destinations;
    }

    /// @notice Split a 32-byte value into the two 128-bit limbs used by the public inputs.
    function limbs(bytes32 v) external pure returns (uint256 hi, uint256 lo) {
        return (uint256(v) >> 128, uint256(v) & type(uint128).max);
    }

    // ── Internal ────────────────────────────────────────────────────────────

    function _drop(address subject, uint8 cause, bytes32 reasonHash) internal {
        Admission memory a = _admissions[subject];
        delete _admissions[subject];
        if (a.granted && txAllowList.readAllowList(subject) == ROLE_ENABLED) txAllowList.setNone(subject);
        emit Dropped(subject, cause, reasonHash);
        _broadcast(MSG_DROP, subject, a.policyHash, a.digest, 0);
    }

    function _broadcast(uint8 kind, address subject, bytes32 policyHash, bytes32 digest, uint64 expiresAt) internal {
        if (address(teleporter) == address(0)) return;
        uint64 s = ++seq;
        bytes memory message = abi.encode(kind, s, subject, policyHash, digest, expiresAt);
        for (uint256 i = 0; i < _destinations.length; ++i) {
            Destination memory d = _destinations[i];
            bytes32 id = teleporter.sendCrossChainMessage(
                TeleporterMessageInput({
                    destinationBlockchainID: d.blockchainId,
                    destinationAddress: d.receiver,
                    feeInfo: TeleporterFeeInfo(address(0), 0),
                    requiredGasLimit: d.gasLimit,
                    allowedRelayerAddresses: new address[](0),
                    message: message
                })
            );
            emit IcmSent(id, s, kind, subject);
        }
    }

    function _join(uint256[] calldata pi, uint256 i) internal pure returns (bytes32) {
        uint256 hi = pi[i];
        uint256 lo = pi[i + 1];
        if (hi >> 128 != 0 || lo >> 128 != 0) revert BadPublicInputs();
        return bytes32((hi << 128) | lo);
    }

    function _u64(uint256 v) internal pure returns (uint64) {
        if (v > type(uint64).max) revert BadPublicInputs();
        return uint64(v);
    }
}
