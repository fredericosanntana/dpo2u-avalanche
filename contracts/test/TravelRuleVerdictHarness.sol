// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {TravelRuleVerdictV1} from "../libraries/TravelRuleVerdictV1.sol";

/// @dev Test-only: exposes the library so the shared vectors can be checked from TypeScript.
contract TravelRuleVerdictHarness {
    function canonical(TravelRuleVerdictV1.Verdict calldata v) external pure returns (bytes memory) {
        return TravelRuleVerdictV1.canonical(v);
    }

    function digest(TravelRuleVerdictV1.Verdict calldata v) external pure returns (bytes32) {
        return TravelRuleVerdictV1.digest(v);
    }
}
