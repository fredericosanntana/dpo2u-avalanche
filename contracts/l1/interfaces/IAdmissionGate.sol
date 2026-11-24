// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice The one view a gate-restricted asset needs from DPO2UL1ComplianceGate.
interface IAdmissionGate {
    function isAdmitted(address subject) external view returns (bool);
}
