// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IAdmissionGate} from "../interfaces/IAdmissionGate.sol";

/// @title DPO2UL1SecurityToken — TEST security token that only gate-admitted wallets may hold
/// @notice Demonstration asset for the CVM track. It is NOT an offer of securities and has no
///         legal effect: it shows how a tokenized security on the DPO2U L1 enforces, at every
///         transfer, that both sides currently hold a ComplianceGate admission (a proven Midnight
///         TravelRuleGate PASS bound to that wallet). The check is in addition to the VM's
///         Transaction AllowList: the AllowList stops a wallet from SENDING transactions, this
///         token also stops a non-admitted wallet from RECEIVING, and it stops an admission that
///         has expired but was not yet removed from the AllowList.
/// @dev Roles: `issuer` mints to admitted wallets, redeems (burns), pauses, and may make a
///      `controllerTransfer` (court order, error correction) to an admitted wallet, logged with a
///      reason hash. Two-step issuer handover.
///
///      DATA PROTECTION (LGPD/GDPR): the token stores balances by wallet only. Who owns a wallet,
///      the KYC file and the Travel Rule data stay with the VASP/issuer off chain. `reasonHash`
///      is a hash of an off-chain record (order number, ticket), never personal data in clear.
contract DPO2UL1SecurityToken is ERC20 {
    error IssuerOnly();
    error ZeroAddress();
    error NotAdmitted(address account);
    error Paused();

    event IssuerTransferStarted(address indexed from, address indexed to);
    event IssuerTransferred(address indexed from, address indexed to);
    event PausedSet(bool paused);
    event ControllerTransfer(address indexed from, address indexed to, uint256 amount, bytes32 reasonHash);
    event Redeemed(address indexed from, uint256 amount, bytes32 reasonHash);

    IAdmissionGate public immutable gate;
    address public issuer;
    address public pendingIssuer;
    bool public paused;
    /// @notice Hash of the off-chain offering documents (term sheet / prospectus of the TEST asset).
    bytes32 public immutable termsHash;

    bool private _controller; // set only for the duration of a controllerTransfer

    modifier onlyIssuer() {
        if (msg.sender != issuer) revert IssuerOnly();
        _;
    }

    constructor(string memory name_, string memory symbol_, IAdmissionGate gate_, address issuer_, bytes32 termsHash_)
        ERC20(name_, symbol_)
    {
        if (address(gate_) == address(0) || issuer_ == address(0)) revert ZeroAddress();
        gate = gate_;
        issuer = issuer_;
        termsHash = termsHash_;
        emit IssuerTransferred(address(0), issuer_);
    }

    /// @notice Whole units only, like shares.
    function decimals() public pure override returns (uint8) {
        return 0;
    }

    function mint(address to, uint256 amount) external onlyIssuer {
        _mint(to, amount);
    }

    function redeem(address from, uint256 amount, bytes32 reasonHash) external onlyIssuer {
        _burn(from, amount);
        emit Redeemed(from, amount, reasonHash);
    }

    /// @notice Moves tokens without the holder's signature. The receiver must still be admitted;
    ///         the sender may be frozen or expired (that is the usual reason for it).
    function controllerTransfer(address from, address to, uint256 amount, bytes32 reasonHash) external onlyIssuer {
        _controller = true;
        _transfer(from, to, amount);
        _controller = false;
        emit ControllerTransfer(from, to, amount, reasonHash);
    }

    function setPaused(bool p) external onlyIssuer {
        paused = p;
        emit PausedSet(p);
    }

    function transferIssuer(address next) external onlyIssuer {
        if (next == address(0)) revert ZeroAddress();
        pendingIssuer = next;
        emit IssuerTransferStarted(issuer, next);
    }

    function acceptIssuer() external {
        if (msg.sender != pendingIssuer) revert IssuerOnly();
        emit IssuerTransferred(issuer, msg.sender);
        issuer = msg.sender;
        pendingIssuer = address(0);
    }

    /// @notice What a transfer would hit, without sending it (for wallets and the DvP contract).
    function canTransfer(address from, address to) public view returns (bool) {
        return !paused && gate.isAdmitted(from) && gate.isAdmitted(to);
    }

    function _update(address from, address to, uint256 value) internal override {
        if (to != address(0) && !gate.isAdmitted(to)) revert NotAdmitted(to); // mint and transfers
        if (from != address(0) && to != address(0) && !_controller) {
            if (paused) revert Paused();
            if (!gate.isAdmitted(from)) revert NotAdmitted(from);
        }
        super._update(from, to, value);
    }
}
