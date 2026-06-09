// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.13;

import {Script} from "forge-std/Script.sol";
import {PrivateBond} from "../src/PrivateBond.sol";
import {HonkVerifier} from "../src/Verifier.sol";

contract PrivateBondScript is Script {
    HonkVerifier public verifier;
    PrivateBond public privateBond;
    address public owner;

    // Bond identifier - set via environment or hardcode for testing
    // Can be keccak256(ISIN), keccak256(CUSIP), or keccak256(BDT_data)
    bytes32 public bondId = keccak256("US0378331005"); // Example ISIN hash

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        owner = msg.sender;

        verifier = new HonkVerifier();
        privateBond = new PrivateBond(bondId, address(verifier), owner);

        vm.stopBroadcast();

        require(address(privateBond) != address(0), "PrivateBond deployment failed");
    }
}
