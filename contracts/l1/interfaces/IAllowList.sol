// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Subnet-EVM AllowList precompile interface (Transaction AllowList at
///         0x0200000000000000000000000000000000000002, Contract Deployer AllowList at
///         0x0200000000000000000000000000000000000000).
/// @dev Roles returned by readAllowList: 0 None, 1 Enabled, 2 Admin, 3 Manager.
interface IAllowList {
    function setAdmin(address addr) external;
    function setEnabled(address addr) external;
    function setManager(address addr) external;
    function setNone(address addr) external;
    function readAllowList(address addr) external view returns (uint256 role);
}
