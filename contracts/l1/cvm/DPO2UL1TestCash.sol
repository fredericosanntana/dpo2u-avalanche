// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @title DPO2UL1TestCash — TEST payment token for the DvP demo (stands in for a BRL stablecoin
///        or tokenized deposit). Minted freely by its owner; no value, local/test networks only.
contract DPO2UL1TestCash is ERC20 {
    error OwnerOnly();

    address public immutable owner;

    constructor() ERC20("DPO2U Test BRL", "tBRL") {
        owner = msg.sender;
    }

    function decimals() public pure override returns (uint8) {
        return 2;
    }

    function mint(address to, uint256 amount) external {
        if (msg.sender != owner) revert OwnerOnly();
        _mint(to, amount);
    }
}
