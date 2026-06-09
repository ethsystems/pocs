// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {PrivateBond} from "../src/PrivateBond.sol";
import {HonkVerifier} from "../src/Verifier.sol";

contract MockVerifier {
    function verify(bytes calldata, bytes32[] calldata) external pure returns (bool) {
        return true;
    }
}

contract PrivateBondTest is Test {
    PrivateBond public privateBond;
    address public issuer;

    // Hardcoded test values from ../../circuits/Prover.toml
    bytes32 constant ROOT = 0x1f8e0ab650e5df57432b1b9eaad2daaa4510a91a0b75bd035051d3bcb7c0151d;
    bytes32 constant NULL_A = 0x1f9622b4d68c1b5b433736ef91c2af7bbff2a6ff7e3de8f7b25f4693493f5df7;
    bytes32 constant NULL_B = 0x2088a1456156a7637b04252cc2cb44e7afec6a73ed8913d1d9166c988fe51948;
    bytes32 constant COMM_OUT_A = 0x1156c6bc9367cc966088ceedb112f454eeca564ce36c0af52a1a6dbc8d57162e;
    bytes32 constant COMM_OUT_B = 0x1b3df58b47ca4b3e800b6bd238d89a9d78a64245825070dcf50e56f9110a509c;
    bytes32 constant MATURITY = bytes32(uint256(1893456000));
    // Example bond identifier (could be hash of ISIN/CUSIP or BDT data)
    bytes32 constant BOND_ID = keccak256("US0378331005"); // Example ISIN hash

    function setUp() public {
        issuer = address(this);
        MockVerifier mockVerifier = new MockVerifier();
        privateBond = new PrivateBond(BOND_ID, address(mockVerifier), issuer);
    }

    function testMintBond() public {
        bytes32 comm = 0x1de409fb2319657514027650e41731fc3c5b77448fdd2b9aceeda9cf95c499e7;
        privateBond.mint(comm);
        // After minting, the contract should have stored this commitment
        assertEq(privateBond.commitments(0), comm);
    }

    function testMintBatch() public {
        bytes32[] memory commitments = new bytes32[](2);
        commitments[0] = 0x1de409fb2319657514027650e41731fc3c5b77448fdd2b9aceeda9cf95c499e7;
        commitments[1] = 0x08b7a207093e941afad82cf336de7e3c99fad595b2877316e832b4b2ca3ec723;
        privateBond.mintBatch(commitments);
        require(privateBond.commitments(0) == commitments[0]);
    }

    function testAtomicSwap() public {
        privateBond.mint(0x1de409fb2319657514027650e41731fc3c5b77448fdd2b9aceeda9cf95c499e7);
        bytes32 currentRoot = privateBond.buildMerkleRoot();

        bytes32[] memory inputsA = new bytes32[](4);
        inputsA[0] = currentRoot;
        inputsA[1] = NULL_A;
        inputsA[2] = COMM_OUT_A;
        inputsA[3] = MATURITY;

        bytes32[] memory inputsB = new bytes32[](4);
        inputsB[0] = currentRoot;
        inputsB[1] = NULL_B;
        inputsB[2] = COMM_OUT_B;
        inputsB[3] = MATURITY;

        privateBond.atomicSwap("", inputsA, "", inputsB);
        assertTrue(privateBond.nullifiers(NULL_A));
    }

    function testPreventDoubleSpend() public {
        privateBond.mint(0x1de409fb2319657514027650e41731fc3c5b77448fdd2b9aceeda9cf95c499e7);
        bytes32 currentRoot = privateBond.buildMerkleRoot();

        bytes32[] memory inputsA = new bytes32[](4);
        inputsA[0] = currentRoot;
        inputsA[1] = NULL_A;
        inputsA[2] = COMM_OUT_A;
        inputsA[3] = MATURITY;

        bytes32[] memory inputsB = new bytes32[](4);
        inputsB[0] = currentRoot;
        inputsB[1] = NULL_B;
        inputsB[2] = COMM_OUT_B;
        inputsB[3] = MATURITY;

        privateBond.atomicSwap("", inputsA, "", inputsB);
        vm.expectRevert("Note A already spent");
        privateBond.atomicSwap("", inputsA, "", inputsB);
    }

    function testPreventPostMaturityTrade() public {
        privateBond.mint(0x1de409fb2319657514027650e41731fc3c5b77448fdd2b9aceeda9cf95c499e7);
        bytes32 currentRoot = privateBond.buildMerkleRoot();
        vm.warp(1893456000 + 1 days);

        bytes32[] memory inputsA = new bytes32[](4);
        inputsA[0] = currentRoot;
        inputsA[1] = NULL_A;
        inputsA[2] = COMM_OUT_A;
        inputsA[3] = MATURITY;

        bytes32[] memory inputsB = new bytes32[](4);
        inputsB[0] = currentRoot;
        inputsB[1] = NULL_B;
        inputsB[2] = COMM_OUT_B;
        inputsB[3] = MATURITY;

        vm.expectRevert("Bond A already matured");
        privateBond.atomicSwap("", inputsA, "", inputsB);
    }

    function testBurnAtMaturity() public {
        privateBond.mint(0x1de409fb2319657514027650e41731fc3c5b77448fdd2b9aceeda9cf95c499e7);
        bytes32 currentRoot = privateBond.buildMerkleRoot();
        vm.warp(1893456000);

        bytes32[2] memory nullsIn = [NULL_A, NULL_B];
        bytes32[2] memory commsOut = [bytes32(0), bytes32(0)];
        privateBond.burn("", currentRoot, nullsIn, commsOut, MATURITY, bytes32(uint256(1)));
        assertTrue(privateBond.nullifiers(NULL_A));
    }

    function testPreventEarlyRedemption() public {
        privateBond.mint(0x1de409fb2319657514027650e41731fc3c5b77448fdd2b9aceeda9cf95c499e7);
        bytes32 currentRoot = privateBond.buildMerkleRoot();
        vm.warp(1893456000 - 365 days);

        bytes32[2] memory nullsIn = [NULL_A, NULL_B];
        bytes32[2] memory commsOut = [bytes32(0), bytes32(0)];
        vm.expectRevert("Bond not at maturity yet");
        privateBond.burn("", currentRoot, nullsIn, commsOut, MATURITY, bytes32(uint256(1)));
    }

    function testPreventDoubleRedemption() public {
        privateBond.mint(0x1de409fb2319657514027650e41731fc3c5b77448fdd2b9aceeda9cf95c499e7);
        bytes32 currentRoot = privateBond.buildMerkleRoot();
        vm.warp(1893456000);

        bytes32[2] memory nullsIn = [NULL_A, NULL_B];
        bytes32[2] memory commsOut = [bytes32(0), bytes32(0)];
        privateBond.burn("", currentRoot, nullsIn, commsOut, MATURITY, bytes32(uint256(1)));
        vm.expectRevert("Note 0 already spent");
        privateBond.burn("", currentRoot, nullsIn, commsOut, MATURITY, bytes32(uint256(1)));
    }

    function testInvalidRoot() public {
        bytes32 badRoot = 0xdead0000000000000000000000000000dead0000000000000000000000000000;
        bytes32[2] memory nullsIn = [NULL_A, NULL_B];
        bytes32[2] memory commsOut = [bytes32(0), bytes32(0)];
        vm.expectRevert("Invalid Merkle Root");
        privateBond.burn("", badRoot, nullsIn, commsOut, MATURITY, bytes32(uint256(1)));
    }

    function testInvalidRedemptionFlag() public {
        privateBond.mint(0x1de409fb2319657514027650e41731fc3c5b77448fdd2b9aceeda9cf95c499e7);
        bytes32 currentRoot = privateBond.buildMerkleRoot();
        vm.warp(1893456000);

        bytes32[2] memory nullsIn = [NULL_A, NULL_B];
        bytes32[2] memory commsOut = [bytes32(0), bytes32(0)];
        vm.expectRevert("Output notes must have 0 value for redemption");
        privateBond.burn("", currentRoot, nullsIn, commsOut, MATURITY, bytes32(uint256(0)));
    }

    function testOnlyOwnerCanSwap() public {
        address attacker = address(0xDEAD);
        bytes32[] memory inputs = new bytes32[](4);

        vm.prank(attacker);
        vm.expectRevert();
        privateBond.atomicSwap("", inputs, "", inputs);
    }

    function testIdenticalNullifiers() public {
        privateBond.mint(0x1de409fb2319657514027650e41731fc3c5b77448fdd2b9aceeda9cf95c499e7);
        bytes32 currentRoot = privateBond.buildMerkleRoot();

        bytes32[] memory inputsA = new bytes32[](4);
        inputsA[0] = currentRoot;
        inputsA[1] = NULL_A;
        inputsA[2] = COMM_OUT_A;
        inputsA[3] = MATURITY;

        bytes32[] memory inputsB = new bytes32[](4);
        inputsB[0] = currentRoot;
        inputsB[1] = NULL_A;
        inputsB[2] = COMM_OUT_B;
        inputsB[3] = MATURITY;

        vm.expectRevert("Identical nullifiers");
        privateBond.atomicSwap("", inputsA, "", inputsB);
    }
}
