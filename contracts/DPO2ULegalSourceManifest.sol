// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title DPO2ULegalSourceManifest — law -> pack traceability on Avalanche
/// @notice Joins the two existing DPO2U designs:
///         - Solana `legal_source_manifest`: one versioned manifest per jurisdiction
///           (content hash of the canonical corpus, effective date, source URI);
///         - Midnight `LegalSourceManifest.compact`: write-once citation anchors
///           (citationId -> canonical statute source hash).
///         A policy pack (packHash in the registry) cites statutes; anyone can check that
///         each cited statute resolves to the anchored source, and which corpus version it
///         came from. Nothing here is personal data: only hashes of public law.
/// @dev Manifest versions are append-only: an attestation sealed against version N keeps
///      pointing at an immutable record even after N+1 is published. Citation anchors are
///      write-once; a changed statute gets a new citation id (e.g. H("LGPD|Art.18|v2")).
contract DPO2ULegalSourceManifest {
    error AdminOnly();
    error NotCurator();
    error NotAuthorized();
    error ZeroAddress();
    error ZeroHash();
    error EmptyJurisdiction();
    error EffectiveDateBackwards();
    error UnknownManifest();
    error CitationExists();
    error UnknownCitation();
    error LengthMismatch();

    struct Manifest {
        bytes32 contentHash; // hash of the canonical corpus snapshot
        uint64 effectiveDate; // unix seconds the corpus is in force from
        uint64 publishedAt;
        address curator;
        string sourceUri; // where the snapshot can be fetched (IPFS, official gazette)
    }

    struct CitationAnchor {
        bytes32 sourceHash; // canonical hash of the statute text
        bytes16 jurisdiction; // same ASCII code as the Solana seed, NUL-padded
        uint32 manifestVersion; // corpus version the citation was taken from
        uint64 anchoredAt;
    }

    address public admin;
    address public pendingAdmin;
    mapping(address => bool) public curators;

    mapping(bytes16 => uint32) public latestVersion; // 0 = no manifest yet
    mapping(bytes16 => mapping(uint32 => Manifest)) private _manifests;
    mapping(bytes32 => CitationAnchor) private _citations;
    uint256 public citationCount;

    event CuratorSet(address indexed curator, bool allowed);
    event AdminTransferStarted(address indexed from, address indexed to);
    event AdminTransferred(address indexed from, address indexed to);
    event ManifestPublished(
        bytes16 indexed jurisdiction, uint32 indexed version, bytes32 contentHash, uint64 effectiveDate, string sourceUri
    );
    event CitationAnchored(
        bytes32 indexed citationId, bytes16 indexed jurisdiction, bytes32 sourceHash, uint32 manifestVersion
    );

    modifier onlyAdmin() {
        if (msg.sender != admin) revert AdminOnly();
        _;
    }

    modifier onlyCurator() {
        if (!curators[msg.sender]) revert NotCurator();
        _;
    }

    constructor(address admin_) {
        if (admin_ == address(0)) revert ZeroAddress();
        admin = admin_;
    }

    // ── Admin ───────────────────────────────────────────────────────────────

    function setCurator(address curator, bool allowed) external onlyAdmin {
        if (curator == address(0)) revert ZeroAddress();
        curators[curator] = allowed;
        emit CuratorSet(curator, allowed);
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

    // ── Curation ────────────────────────────────────────────────────────────

    /// @notice Publish the next corpus version for `jurisdiction`. Earlier versions stay readable.
    function publishManifest(bytes16 jurisdiction, bytes32 contentHash, uint64 effectiveDate, string calldata sourceUri)
        external
        onlyCurator
        returns (uint32 version)
    {
        if (jurisdiction == bytes16(0)) revert EmptyJurisdiction();
        if (contentHash == bytes32(0)) revert ZeroHash();
        uint32 prev = latestVersion[jurisdiction];
        if (prev != 0 && effectiveDate < _manifests[jurisdiction][prev].effectiveDate) revert EffectiveDateBackwards();

        version = prev + 1;
        latestVersion[jurisdiction] = version;
        _manifests[jurisdiction][version] = Manifest({
            contentHash: contentHash,
            effectiveDate: effectiveDate,
            publishedAt: uint64(block.timestamp),
            curator: msg.sender,
            sourceUri: sourceUri
        });
        emit ManifestPublished(jurisdiction, version, contentHash, effectiveDate, sourceUri);
    }

    /// @notice Anchor a citation (write-once) against an existing manifest version.
    function anchorCitation(bytes32 citationId, bytes32 sourceHash, bytes16 jurisdiction, uint32 manifestVersion)
        external
        onlyCurator
    {
        if (citationId == bytes32(0) || sourceHash == bytes32(0)) revert ZeroHash();
        if (manifestVersion == 0 || manifestVersion > latestVersion[jurisdiction]) revert UnknownManifest();
        if (_citations[citationId].sourceHash != bytes32(0)) revert CitationExists();

        _citations[citationId] = CitationAnchor({
            sourceHash: sourceHash,
            jurisdiction: jurisdiction,
            manifestVersion: manifestVersion,
            anchoredAt: uint64(block.timestamp)
        });
        unchecked {
            ++citationCount;
        }
        emit CitationAnchored(citationId, jurisdiction, sourceHash, manifestVersion);
    }

    // ── Reads ───────────────────────────────────────────────────────────────

    function getManifest(bytes16 jurisdiction, uint32 version) public view returns (Manifest memory m) {
        m = _manifests[jurisdiction][version];
        if (m.contentHash == bytes32(0)) revert UnknownManifest();
    }

    function getLatestManifest(bytes16 jurisdiction) external view returns (uint32 version, Manifest memory m) {
        version = latestVersion[jurisdiction];
        m = getManifest(jurisdiction, version);
    }

    function getCitation(bytes32 citationId) public view returns (CitationAnchor memory c) {
        c = _citations[citationId];
        if (c.sourceHash == bytes32(0)) revert UnknownCitation();
    }

    /// @notice True if `candidateHash` is the anchored source of `citationId`.
    function verifySource(bytes32 citationId, bytes32 candidateHash) public view returns (bool) {
        return getCitation(citationId).sourceHash == candidateHash;
    }

    /// @notice Batch check for a policy pack: every citation must resolve to its candidate hash.
    ///         Unknown citations revert, so a pack cannot cite an unanchored statute.
    function verifySources(bytes32[] calldata citationIds, bytes32[] calldata candidateHashes)
        external
        view
        returns (bool)
    {
        if (citationIds.length != candidateHashes.length) revert LengthMismatch();
        for (uint256 i; i < citationIds.length; ++i) {
            if (!verifySource(citationIds[i], candidateHashes[i])) return false;
        }
        return true;
    }

    /// @notice Citation ids follow the Midnight convention: keccak256("<JURISDICTION>|<article>").
    function citationIdOf(string calldata jurisdiction, string calldata article) external pure returns (bytes32) {
        return keccak256(abi.encodePacked(jurisdiction, "|", article));
    }
}
