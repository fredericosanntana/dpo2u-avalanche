// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {DPO2UPassportOracleV2} from "../DPO2UPassportOracleV2.sol";

/// @notice TEST ONLY: a later version used to check upgrades keep state.
contract PassportOracleV3Mock is DPO2UPassportOracleV2 {
    function version() external pure override returns (string memory) {
        return "3-mock";
    }
}
