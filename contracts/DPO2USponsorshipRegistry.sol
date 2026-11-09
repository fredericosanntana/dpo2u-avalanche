// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {DPO2UPassportOracle} from "./DPO2UPassportOracle.sol";

/// @title DPO2USponsorshipRegistry — SPSAV sponsorship of a partner, on-chain
/// @notice On-chain counterpart of the control-plane SponsorshipService (Res. BCB 520
///         arts. 32-42): a licensed SPSAV sponsors a contracted relevant-service provider.
///         - only a licensed SPSAV (allowlisted by the admin) proposes;
///         - only the partner itself consents (msg.sender), and consent activates only if
///           the partner holds a valid passport for every required pack at `minTier`;
///         - the accountable director (art. 42) is stored as a hash: no personal data;
///         - `isActive` re-checks the passports on every read, so a suspended, revoked or
///           expired passport turns the sponsorship off in the same block, with no relayer.
///           Silence counts as non-compliance.
contract DPO2USponsorshipRegistry {
    error AdminOnly();
    error NotAuthorized();
    error NotLicensedSponsor();
    error ZeroAddress();
    error ZeroValue();
    error SelfSponsorship();
    error InvalidTier();
    error UnknownSponsorship();
    error InvalidState();
    error PassportNotQualifying();

    enum Status {
        NONE,
        PROPOSED,
        ACTIVE,
        CONSENT_REVOKED,
        ENDED
    }

    struct Sponsorship {
        address sponsor;
        address partner;
        DPO2UPassportOracle.Tier minTier;
        Status status;
        uint64 proposedAt;
        uint64 updatedAt;
        bytes32 accountableDirectorHash; // H(director identity), art. 42
        bytes32[] requiredPackIds;
    }

    DPO2UPassportOracle public immutable oracle;
    address public admin;
    address public pendingAdmin;
    mapping(address => bool) public licensedSponsors;

    uint256 public sponsorshipCount;
    mapping(uint256 => Sponsorship) private _sponsorships;

    event SponsorLicensed(address indexed sponsor, bool licensed);
    event AdminTransferStarted(address indexed from, address indexed to);
    event AdminTransferred(address indexed from, address indexed to);
    event SponsorshipProposed(
        uint256 indexed id,
        address indexed sponsor,
        address indexed partner,
        bytes32[] requiredPackIds,
        DPO2UPassportOracle.Tier minTier,
        bytes32 accountableDirectorHash
    );
    event ConsentGranted(uint256 indexed id, address indexed partner);
    event ConsentRevoked(uint256 indexed id, address indexed partner);
    event SponsorshipEnded(uint256 indexed id, address indexed by, bytes32 reasonHash);

    modifier onlyAdmin() {
        if (msg.sender != admin) revert AdminOnly();
        _;
    }

    constructor(address admin_, DPO2UPassportOracle oracle_) {
        if (admin_ == address(0) || address(oracle_) == address(0)) revert ZeroAddress();
        admin = admin_;
        oracle = oracle_;
    }

    // ── Admin ───────────────────────────────────────────────────────────────

    /// @notice Allowlist of SPSAVs licensed by the BCB. Delicensing turns their sponsorships off.
    function setLicensedSponsor(address sponsor, bool licensed) external onlyAdmin {
        if (sponsor == address(0)) revert ZeroAddress();
        licensedSponsors[sponsor] = licensed;
        emit SponsorLicensed(sponsor, licensed);
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

    // ── Lifecycle ───────────────────────────────────────────────────────────

    function propose(
        address partner,
        bytes32[] calldata requiredPackIds,
        DPO2UPassportOracle.Tier minTier,
        bytes32 accountableDirectorHash
    ) external returns (uint256 id) {
        if (!licensedSponsors[msg.sender]) revert NotLicensedSponsor();
        if (partner == address(0)) revert ZeroAddress();
        if (partner == msg.sender) revert SelfSponsorship();
        if (requiredPackIds.length == 0 || accountableDirectorHash == bytes32(0)) revert ZeroValue();
        if (minTier == DPO2UPassportOracle.Tier.NONE) revert InvalidTier();
        for (uint256 i; i < requiredPackIds.length; ++i) {
            if (requiredPackIds[i] == bytes32(0)) revert ZeroValue();
        }

        id = ++sponsorshipCount;
        Sponsorship storage s = _sponsorships[id];
        s.sponsor = msg.sender;
        s.partner = partner;
        s.minTier = minTier;
        s.status = Status.PROPOSED;
        s.proposedAt = uint64(block.timestamp);
        s.updatedAt = uint64(block.timestamp);
        s.accountableDirectorHash = accountableDirectorHash;
        s.requiredPackIds = requiredPackIds;
        emit SponsorshipProposed(id, msg.sender, partner, requiredPackIds, minTier, accountableDirectorHash);
    }

    /// @notice Only the partner consents to share its evidence. Activates only with a
    ///         qualifying passport right now. Also re-consents after a revocation.
    function grantConsent(uint256 id) external {
        Sponsorship storage s = _require(id);
        if (msg.sender != s.partner) revert NotAuthorized();
        if (s.status != Status.PROPOSED && s.status != Status.CONSENT_REVOKED) revert InvalidState();
        if (!_passportsQualify(s)) revert PassportNotQualifying();
        s.status = Status.ACTIVE;
        s.updatedAt = uint64(block.timestamp);
        emit ConsentGranted(id, msg.sender);
    }

    function revokeConsent(uint256 id) external {
        Sponsorship storage s = _require(id);
        if (msg.sender != s.partner) revert NotAuthorized();
        if (s.status != Status.ACTIVE) revert InvalidState();
        s.status = Status.CONSENT_REVOKED;
        s.updatedAt = uint64(block.timestamp);
        emit ConsentRevoked(id, msg.sender);
    }

    /// @notice Terminal. The sponsor or the partner can end it; the admin too (e.g. license lost).
    function end(uint256 id, bytes32 reasonHash) external {
        Sponsorship storage s = _require(id);
        if (msg.sender != s.sponsor && msg.sender != s.partner && msg.sender != admin) revert NotAuthorized();
        if (s.status == Status.ENDED) revert InvalidState();
        s.status = Status.ENDED;
        s.updatedAt = uint64(block.timestamp);
        emit SponsorshipEnded(id, msg.sender, reasonHash);
    }

    // ── Reads ───────────────────────────────────────────────────────────────

    /// @notice Live answer: consented, sponsor still licensed, and the partner's passports
    ///         still valid for every required pack at `minTier`, in this block.
    function isActive(uint256 id) public view returns (bool) {
        Sponsorship storage s = _sponsorships[id];
        return s.status == Status.ACTIVE && licensedSponsors[s.sponsor] && _passportsQualify(s);
    }

    function getSponsorship(uint256 id) external view returns (Sponsorship memory) {
        return _require(id);
    }

    // ── Internal ────────────────────────────────────────────────────────────

    function _require(uint256 id) private view returns (Sponsorship storage s) {
        s = _sponsorships[id];
        if (s.status == Status.NONE) revert UnknownSponsorship();
    }

    function _passportsQualify(Sponsorship storage s) private view returns (bool) {
        return oracle.isValidAll(oracle.subjectOf(s.partner), s.requiredPackIds, s.minTier);
    }
}
