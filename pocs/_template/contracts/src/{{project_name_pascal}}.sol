// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.13;

contract {{project_name_pascal}} {
    uint256 public number;

    function setNumber(uint256 newNumber) public {
        number = newNumber;
    }

    function increment() public {
        number++;
    }
}
