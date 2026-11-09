// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {DPO2UPassportOracle} from "../DPO2UPassportOracle.sol";

/// @title PassportGatedSettlement — example consumer of the DPO2U passport oracle
/// @notice A minimal settlement desk for a licensed SPSAV (Res. BCB 520): it only moves
///         AVAX between two accounts when BOTH hold a valid passport for the required pack
///         at the required tier, at the moment of the transfer. A counterparty whose passport
///         expired, was suspended or never existed is refused — silence = non-compliance.
/// @dev Example only (not audited). The pack and tier are fixed at deploy, the way a
///      sponsorship pins `requiredPackIds` and `minTier`.
contract PassportGatedSettlement {
    error PayerNotCompliant();
    error PayeeNotCompliant();
    error ZeroAmount();
    error TransferFailed();

    DPO2UPassportOracle public immutable oracle;
    bytes32 public immutable requiredPackId;
    DPO2UPassportOracle.Tier public immutable minTier;

    event Settled(address indexed payer, address indexed payee, uint256 amount);

    constructor(DPO2UPassportOracle oracle_, bytes32 requiredPackId_, DPO2UPassportOracle.Tier minTier_) {
        oracle = oracle_;
        requiredPackId = requiredPackId_;
        minTier = minTier_;
    }

    function settle(address payable payee) external payable {
        if (msg.value == 0) revert ZeroAmount();
        if (!oracle.isAccountValid(msg.sender, requiredPackId, minTier)) revert PayerNotCompliant();
        if (!oracle.isAccountValid(payee, requiredPackId, minTier)) revert PayeeNotCompliant();
        (bool ok, ) = payee.call{value: msg.value}("");
        if (!ok) revert TransferFailed();
        emit Settled(msg.sender, payee, msg.value);
    }
}
