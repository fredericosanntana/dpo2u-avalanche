// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IDPO2UAttestation} from "./interfaces/IDPO2UAttestation.sol";
import {Initializable} from "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

/// @title DPO2UPassportOracleV2 — upgradeable PassportOracle (UUPS proxy, admin = Safe)
/// @notice Same rules as DPO2UPassportOracle (v1, verified on Fuji), behind an ERC-1967 proxy so
///         consumers keep one address across fixes. Only the admin (a Safe multisig in
///         production) can upgrade; the implementation cannot be initialized directly.
///         Storage is append-only across versions (see `__gap`).
///
/// v1 description:
/// @notice EVM mirror of the control-plane Passport (PSAV spec §3.4): a subject holds,
///         per policy pack, a passport with a tier, a status and a mandatory expiry.
///         Any contract asks `isValid(subject, packId, minTier)` before dealing with a
///         counterparty. Raw identity never goes on-chain: the subject is
///         keccak256 of its CAIP-10 account (see `subjectOf`).
/// @dev Invariants (tested):
///      - Silence = non-compliance: every passport expires, and an expired one is not valid
///        without anyone having to act.
///      - A passport is issued only on top of a seal that exists in the registry, is not
///        revoked and is not FAIL. The seal reference is stored, so anyone can audit it.
///      - Suspended and revoked are not valid; neither can be undone. A new passport (new
///        id, backed by a usable seal) is the only way back, and the history stays in the events.
///      - The seal must be about the same subject and the same pack hash as the passport.
///      - A REVIEW seal can back only a tier1-machine-only passport; higher tiers need PASS.
///      - Validity is capped by `maxValidity`, and tier2/tier3 also by 31 days.
///      - A passport id is used once (anti-replay).
///      - Tier order matches the control plane: tier1-machine-only < tier1 < tier2 < tier3.
///        `minTier` NONE is refused, so a caller cannot ask "any passport, even none".
contract DPO2UPassportOracleV2 is Initializable, UUPSUpgradeable {
    error NotAuthorized();
    error AdminOnly();
    error ZeroAddress();
    error InvalidTier();
    error InvalidExpiry();
    error ValidityTooLong();
    error PassportIdUsed();
    error PassportNotFound();
    error PassportNotValid();
    error SealNotFound();
    error SealNotUsable();
    error SealMismatch();
    error ZeroValue();

    /// Rank order mirrors control-plane TIER_RANK (+1, NONE = 0 = no passport).
    enum Tier {
        NONE,
        TIER1_MACHINE_ONLY,
        TIER1,
        TIER2,
        TIER3
    }

    enum Status {
        NONE,
        VALID,
        SUSPENDED,
        REVOKED
    }

    struct Passport {
        bytes32 passportId; // H(control-plane passport id)
        bytes32 packHash; // pinned hash of the exact rule set evaluated
        Tier tier;
        Status status;
        uint64 issuedAt;
        uint64 expiresAt;
        address issuer;
        bytes32 sealUseCaseId; // registry reference of the sealed run
        bytes32 sealEvidenceHash;
    }

    IDPO2UAttestation public registry;
    /// Upper bound on validity (control plane: 365 days for tier1, 31 for tier2/3).
    uint64 public maxValidity;
    /// Control-plane TIER_WINDOW_DAYS for tier2 and tier3.
    uint64 public constant HIGH_TIER_MAX_VALIDITY = 31 days;

    address public admin;
    address public pendingAdmin;

    mapping(address => bool) private _issuers;
    mapping(bytes32 => mapping(bytes32 => Passport)) private _passports; // subject => packId => passport
    mapping(bytes32 => bool) private _usedPassportIds;

    event IssuerAuthorized(address indexed issuer, bool allowed);
    event AdminTransferStarted(address indexed from, address indexed to);
    event AdminTransferred(address indexed from, address indexed to);
    event PassportIssued(
        bytes32 indexed subject,
        bytes32 indexed packId,
        bytes32 indexed passportId,
        Tier tier,
        uint64 expiresAt,
        bytes32 sealUseCaseId,
        bytes32 sealEvidenceHash
    );
    event PassportSuspended(bytes32 indexed subject, bytes32 indexed packId, bytes32 indexed passportId, bytes32 reasonHash);
    event PassportRevoked(bytes32 indexed subject, bytes32 indexed packId, bytes32 indexed passportId, bytes32 reasonHash);

    modifier onlyAdmin() {
        if (msg.sender != admin) revert AdminOnly();
        _;
    }

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() {
        _disableInitializers();
    }

    function initialize(address admin_, address registry_, uint64 maxValidity_) external initializer {
        if (admin_ == address(0) || registry_ == address(0)) revert ZeroAddress();
        if (maxValidity_ == 0) revert InvalidExpiry();
        admin = admin_;
        registry = IDPO2UAttestation(registry_);
        maxValidity = maxValidity_;
    }

    // ── Admin ───────────────────────────────────────────────────────────────

    function authorizeIssuer(address issuer, bool allowed) external onlyAdmin {
        if (issuer == address(0)) revert ZeroAddress();
        _issuers[issuer] = allowed;
        emit IssuerAuthorized(issuer, allowed);
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

    /// @dev Upgrades are admin-only. With the admin on a Safe, an upgrade needs the multisig.
    function _authorizeUpgrade(address) internal override onlyAdmin {}

    function version() external pure virtual returns (string memory) {
        return "2";
    }

    // ── Write ───────────────────────────────────────────────────────────────

    /// @notice Issue (or replace) the passport of `subject` for `packId`. The new passport
    ///         supersedes the previous one for the same pack, whatever its state.
    function issuePassport(
        bytes32 subject,
        bytes32 packId,
        bytes32 packHash,
        Tier tier,
        uint64 expiresAt,
        bytes32 passportId,
        bytes32 sealUseCaseId,
        bytes32 sealEvidenceHash
    ) external {
        if (!_issuers[msg.sender]) revert NotAuthorized();
        if (subject == bytes32(0) || packId == bytes32(0) || packHash == bytes32(0) || passportId == bytes32(0)) {
            revert ZeroValue();
        }
        if (tier == Tier.NONE) revert InvalidTier();
        if (expiresAt <= block.timestamp) revert InvalidExpiry();
        uint256 cap = maxValidity;
        if (uint8(tier) >= uint8(Tier.TIER2) && cap > HIGH_TIER_MAX_VALIDITY) cap = HIGH_TIER_MAX_VALIDITY;
        if (expiresAt - block.timestamp > cap) revert ValidityTooLong();
        if (_usedPassportIds[passportId]) revert PassportIdUsed();
        _requireUsableSeal(sealUseCaseId, sealEvidenceHash, subject, packHash, tier);

        _usedPassportIds[passportId] = true;
        _passports[subject][packId] = Passport({
            passportId: passportId,
            packHash: packHash,
            tier: tier,
            status: Status.VALID,
            issuedAt: uint64(block.timestamp),
            expiresAt: expiresAt,
            issuer: msg.sender,
            sealUseCaseId: sealUseCaseId,
            sealEvidenceHash: sealEvidenceHash
        });
        emit PassportIssued(subject, packId, passportId, tier, expiresAt, sealUseCaseId, sealEvidenceHash);
    }

    /// @notice Suspension must reach counterparties fast; it takes effect in the same block.
    function suspendPassport(bytes32 subject, bytes32 packId, bytes32 reasonHash) external {
        Passport storage p = _current(subject, packId);
        if (p.status != Status.VALID) revert PassportNotValid();
        p.status = Status.SUSPENDED;
        emit PassportSuspended(subject, packId, p.passportId, reasonHash);
    }

    /// @notice Revocation is terminal for this passport id (suspended ones can still be revoked).
    function revokePassport(bytes32 subject, bytes32 packId, bytes32 reasonHash) external {
        Passport storage p = _current(subject, packId);
        if (p.status == Status.REVOKED) revert PassportNotValid();
        p.status = Status.REVOKED;
        emit PassportRevoked(subject, packId, p.passportId, reasonHash);
    }

    // ── Read ────────────────────────────────────────────────────────────────

    function isIssuer(address who) external view returns (bool) {
        return _issuers[who];
    }

    function getPassport(bytes32 subject, bytes32 packId) external view returns (Passport memory p) {
        p = _passports[subject][packId];
        if (p.status == Status.NONE) revert PassportNotFound();
    }

    /// @notice The oracle question: does `subject` hold a valid passport for `packId`
    ///         at `minTier` or above, right now?
    function isValid(bytes32 subject, bytes32 packId, Tier minTier) public view returns (bool) {
        if (minTier == Tier.NONE) revert InvalidTier();
        Passport storage p = _passports[subject][packId];
        return p.status == Status.VALID && block.timestamp < p.expiresAt && uint8(p.tier) >= uint8(minTier);
    }

    /// @notice Same question for an EVM account on this chain (subject = H(CAIP-10)).
    function isAccountValid(address account, bytes32 packId, Tier minTier) external view returns (bool) {
        return isValid(subjectOf(account), packId, minTier);
    }

    /// @notice Every pack in `packIds` must be valid at `minTier` (a sponsorship's requiredPackIds).
    function isValidAll(bytes32 subject, bytes32[] calldata packIds, Tier minTier) external view returns (bool) {
        if (packIds.length == 0) revert ZeroValue();
        for (uint256 i; i < packIds.length; ++i) {
            if (!isValid(subject, packIds[i], minTier)) return false;
        }
        return true;
    }

    /// @notice keccak256("eip155:<chainid>:<lowercase 0x address>") — the same subject the
    ///         DPO2U gateway writes for an EVM account (pilot-gateway avalanche-driver).
    function subjectOf(address account) public view returns (bytes32) {
        return keccak256(abi.encodePacked("eip155:", _toDecimal(block.chainid), ":", _toLowerHex(account)));
    }

    // ── Internal ────────────────────────────────────────────────────────────

    function _current(bytes32 subject, bytes32 packId) private view returns (Passport storage p) {
        p = _passports[subject][packId];
        if (p.status == Status.NONE) revert PassportNotFound();
        if (msg.sender != admin && msg.sender != p.issuer) revert NotAuthorized();
    }

    function _requireUsableSeal(bytes32 useCaseId, bytes32 evidenceHash, bytes32 subject, bytes32 packHash, Tier tier)
        private
        view
    {
        IDPO2UAttestation.Attestation memory a;
        try registry.getAttestation(useCaseId, evidenceHash) returns (IDPO2UAttestation.Attestation memory got) {
            a = got;
        } catch {
            revert SealNotFound();
        }
        if (a.revoked || a.verdict == IDPO2UAttestation.Verdict.FAIL || block.timestamp >= a.expiresAt) {
            revert SealNotUsable();
        }
        if (a.verdict == IDPO2UAttestation.Verdict.REVIEW && tier != Tier.TIER1_MACHINE_ONLY) revert SealNotUsable();
        if (a.subject != subject || a.packHash != packHash) revert SealMismatch();
    }

    function _toDecimal(uint256 v) private pure returns (bytes memory out) {
        if (v == 0) return "0";
        uint256 len;
        for (uint256 t = v; t != 0; t /= 10) ++len;
        out = new bytes(len);
        for (; v != 0; v /= 10) out[--len] = bytes1(uint8(48 + (v % 10)));
    }

    function _toLowerHex(address a) private pure returns (bytes memory out) {
        bytes16 digits = "0123456789abcdef";
        out = new bytes(42);
        out[0] = "0";
        out[1] = "x";
        uint160 x = uint160(a);
        for (uint256 i = 41; i > 1; --i) {
            out[i] = digits[x & 0xf];
            x >>= 4;
        }
    }

    /// @dev Reserved slots for future versions (append-only storage).
    uint256[44] private __gap;
}
