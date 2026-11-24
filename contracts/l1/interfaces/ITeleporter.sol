// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Minimal slice of the ICM Contracts (Teleporter) interfaces used by the L1 gate and the
///         C-Chain receiver. Field order matches TeleporterMessageInput in ava-labs/icm-contracts.
struct TeleporterFeeInfo {
    address feeTokenAddress;
    uint256 amount;
}

struct TeleporterMessageInput {
    bytes32 destinationBlockchainID;
    address destinationAddress;
    TeleporterFeeInfo feeInfo;
    uint256 requiredGasLimit;
    address[] allowedRelayerAddresses;
    bytes message;
}

interface ITeleporterMessenger {
    function sendCrossChainMessage(TeleporterMessageInput calldata messageInput) external returns (bytes32 messageID);
}

interface ITeleporterReceiver {
    function receiveTeleporterMessage(bytes32 sourceBlockchainID, address originSenderAddress, bytes calldata message) external;
}
