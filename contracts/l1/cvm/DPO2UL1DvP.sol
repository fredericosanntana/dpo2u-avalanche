// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IAdmissionGate} from "../interfaces/IAdmissionGate.sol";

/// @title DPO2UL1DvP — delivery versus payment between two gate-admitted wallets
/// @notice The seller proposes a trade (asset amount for cash amount, named buyer, deadline); the
///         buyer settles it. Settlement moves the asset seller -> buyer and the cash buyer ->
///         seller in ONE transaction: if either leg fails (allowance, balance, admission, pause),
///         both revert, so nobody delivers without being paid. No custody: the contract never
///         holds tokens, it only uses the allowances both sides gave it.
/// @dev Both parties must be admitted by the gate at settlement time (checked here for a clear
///      error, and again by a gate-restricted asset on its own transfer).
///
///      DATA PROTECTION (LGPD/GDPR): a trade is wallets, token addresses and amounts. The
///      `termsHash` is a hash of the off-chain trade confirmation; no personal data on chain.
contract DPO2UL1DvP is ReentrancyGuard {
    using SafeERC20 for IERC20;

    error ZeroAddress();
    error BadTrade();
    error NotOpen();
    error Expired();
    error NotParty();
    error NotAdmitted(address account);

    enum State {
        None,
        Open,
        Settled,
        Cancelled
    }

    struct Trade {
        address seller;
        address buyer;
        IERC20 asset;
        uint256 assetAmount;
        IERC20 cash;
        uint256 cashAmount;
        uint64 deadline;
        State state;
        bytes32 termsHash;
    }

    event Proposed(uint256 indexed id, address indexed seller, address indexed buyer, address asset, uint256 assetAmount, address cash, uint256 cashAmount, uint64 deadline, bytes32 termsHash);
    event Settled(uint256 indexed id);
    event Cancelled(uint256 indexed id, address by);

    IAdmissionGate public immutable gate;
    uint256 public nextId = 1;
    mapping(uint256 => Trade) private _trades;

    constructor(IAdmissionGate gate_) {
        if (address(gate_) == address(0)) revert ZeroAddress();
        gate = gate_;
    }

    function propose(
        address buyer,
        IERC20 asset,
        uint256 assetAmount,
        IERC20 cash,
        uint256 cashAmount,
        uint64 deadline,
        bytes32 termsHash
    ) external returns (uint256 id) {
        if (buyer == address(0) || address(asset) == address(0) || address(cash) == address(0)) revert ZeroAddress();
        if (buyer == msg.sender || asset == cash || assetAmount == 0 || cashAmount == 0) revert BadTrade();
        if (deadline <= block.timestamp) revert Expired();
        if (!gate.isAdmitted(msg.sender)) revert NotAdmitted(msg.sender);
        id = nextId++;
        _trades[id] = Trade(msg.sender, buyer, asset, assetAmount, cash, cashAmount, deadline, State.Open, termsHash);
        emit Proposed(id, msg.sender, buyer, address(asset), assetAmount, address(cash), cashAmount, deadline, termsHash);
    }

    /// @notice Buyer settles: both legs or neither.
    function settle(uint256 id) external nonReentrant {
        Trade storage t = _trades[id];
        if (t.state != State.Open) revert NotOpen();
        if (msg.sender != t.buyer) revert NotParty();
        if (block.timestamp > t.deadline) revert Expired();
        if (!gate.isAdmitted(t.seller)) revert NotAdmitted(t.seller);
        if (!gate.isAdmitted(t.buyer)) revert NotAdmitted(t.buyer);
        t.state = State.Settled;
        t.asset.safeTransferFrom(t.seller, t.buyer, t.assetAmount);
        t.cash.safeTransferFrom(t.buyer, t.seller, t.cashAmount);
        emit Settled(id);
    }

    /// @notice Either party may cancel an open trade; anyone may clear one past its deadline.
    function cancel(uint256 id) external {
        Trade storage t = _trades[id];
        if (t.state != State.Open) revert NotOpen();
        if (msg.sender != t.seller && msg.sender != t.buyer && block.timestamp <= t.deadline) revert NotParty();
        t.state = State.Cancelled;
        emit Cancelled(id, msg.sender);
    }

    function trade(uint256 id) external view returns (Trade memory) {
        return _trades[id];
    }
}
