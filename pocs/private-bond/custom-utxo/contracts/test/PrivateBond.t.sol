// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.13;

import {Test} from "forge-std/Test.sol";
import {PrivateBond, BondPublicInputs} from "../src/PrivateBond.sol";
import {HonkVerifier} from "../src/Verifier.sol";

// Accepts every proof until expectInputs is called; from then on, only proofs whose
// public inputs match an expected list exactly (verify is view, so it cannot record calls)
contract MockVerifier {
    mapping(bytes32 => bool) internal expected;
    bool internal checking;

    function expectInputs(bytes32[] calldata publicInputs) external {
        expected[keccak256(abi.encode(publicInputs))] = true;
        checking = true;
    }

    function verify(bytes calldata, bytes32[] calldata publicInputs) external view returns (bool) {
        return !checking || expected[keccak256(abi.encode(publicInputs))];
    }
}

contract PrivateBondTest is Test {
    PrivateBond public privateBond;
    MockVerifier public mockVerifier;
    address public issuer;

    // Hardcoded test values from ../../circuits/Prover.toml
    bytes32 constant ROOT = 0x1f8e0ab650e5df57432b1b9eaad2daaa4510a91a0b75bd035051d3bcb7c0151d;
    bytes32 constant NULL_A = 0x1f9622b4d68c1b5b433736ef91c2af7bbff2a6ff7e3de8f7b25f4693493f5df7;
    bytes32 constant NULL_B = 0x2088a1456156a7637b04252cc2cb44e7afec6a73ed8913d1d9166c988fe51948;
    bytes32 constant COMM_OUT_A = 0x1156c6bc9367cc966088ceedb112f454eeca564ce36c0af52a1a6dbc8d57162e;
    bytes32 constant COMM_OUT_B = 0x1b3df58b47ca4b3e800b6bd238d89a9d78a64245825070dcf50e56f9110a509c;
    bytes32 constant MATURITY = bytes32(uint256(1893456000));
    // Second-input (dummy) nullifiers and second-output commitments; any distinct values work with the mock
    bytes32 constant NULL_A_PAD = keccak256("NULL_A_PAD");
    bytes32 constant NULL_B_PAD = keccak256("NULL_B_PAD");
    bytes32 constant COMM_PAD_A = keccak256("COMM_PAD_A");
    bytes32 constant COMM_PAD_B = keccak256("COMM_PAD_B");
    bytes32 constant NOTE = 0x1de409fb2319657514027650e41731fc3c5b77448fdd2b9aceeda9cf95c499e7;
    // Example bond identifier (could be hash of ISIN/CUSIP or BDT data)
    bytes32 constant BOND_ID = keccak256("US0378331005"); // Example ISIN hash

    function setUp() public {
        issuer = address(this);
        mockVerifier = new MockVerifier();
        privateBond = new PrivateBond(BOND_ID, address(mockVerifier), issuer);
    }

    // Public inputs in circuit order, redeem flag 0
    function _inputs(bytes32 root, bytes32 nullifier0, bytes32 nullifier1, bytes32 commitment0, bytes32 commitment1)
        internal
        pure
        returns (bytes32[] memory inputs)
    {
        inputs = new bytes32[](BondPublicInputs.LENGTH);
        inputs[BondPublicInputs.ROOT] = root;
        inputs[BondPublicInputs.NULLIFIER_0] = nullifier0;
        inputs[BondPublicInputs.NULLIFIER_1] = nullifier1;
        inputs[BondPublicInputs.COMMITMENT_0] = commitment0;
        inputs[BondPublicInputs.COMMITMENT_1] = commitment1;
        inputs[BondPublicInputs.INPUT_MATURITY_DATE] = MATURITY;
        inputs[BondPublicInputs.OUTPUT_MATURITY_DATE] = MATURITY;
    }

    function _mintAndRoot() internal returns (bytes32) {
        privateBond.mint(NOTE);
        return privateBond.buildMerkleRoot();
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

    function testTransfer() public {
        bytes32 currentRoot = _mintAndRoot();
        mockVerifier.expectInputs(_inputs(currentRoot, NULL_A, NULL_A_PAD, COMM_OUT_A, COMM_PAD_A));

        privateBond.transfer("", currentRoot, [NULL_A, NULL_A_PAD], [COMM_OUT_A, COMM_PAD_A], MATURITY);

        assertTrue(privateBond.nullifiers(NULL_A));
        assertTrue(privateBond.nullifiers(NULL_A_PAD));
        assertEq(privateBond.commitments(1), COMM_OUT_A);
        assertEq(privateBond.commitments(2), COMM_PAD_A);
    }

    // The contract no longer sends the old 5-input list
    function testTransferDoesNotSendOldLayout() public {
        bytes32 currentRoot = _mintAndRoot();
        bytes32[] memory oldLayout = new bytes32[](5);
        oldLayout[0] = currentRoot;
        oldLayout[1] = NULL_A;
        oldLayout[2] = NULL_A_PAD;
        oldLayout[3] = COMM_OUT_A;
        oldLayout[4] = COMM_PAD_A;
        mockVerifier.expectInputs(oldLayout);

        vm.expectRevert("Invalid Transfer Proof");
        privateBond.transfer("", currentRoot, [NULL_A, NULL_A_PAD], [COMM_OUT_A, COMM_PAD_A], MATURITY);
    }

    function testTransferPreventDoubleSpend() public {
        bytes32 currentRoot = _mintAndRoot();

        privateBond.transfer("", currentRoot, [NULL_A, NULL_A_PAD], [COMM_OUT_A, COMM_PAD_A], MATURITY);
        vm.expectRevert("Note 0 already spent");
        privateBond.transfer("", currentRoot, [NULL_A, NULL_A_PAD], [COMM_OUT_A, COMM_PAD_A], MATURITY);
    }

    // A note spent in the second input slot cannot be spent again
    function testTransferRejectsSpentSecondInput() public {
        bytes32 currentRoot = _mintAndRoot();

        privateBond.transfer("", currentRoot, [NULL_A, NULL_A_PAD], [COMM_OUT_A, COMM_PAD_A], MATURITY);
        vm.expectRevert("Note 1 already spent");
        privateBond.transfer("", currentRoot, [NULL_B, NULL_A_PAD], [COMM_OUT_B, COMM_PAD_B], MATURITY);
    }

    function testTransferIdenticalNullifiers() public {
        bytes32 currentRoot = _mintAndRoot();

        vm.expectRevert("Identical nullifiers");
        privateBond.transfer("", currentRoot, [NULL_A, NULL_A], [COMM_OUT_A, COMM_PAD_A], MATURITY);
    }

    // A bond at maturity can no longer move; burn takes over from that timestamp
    function testPreventPostMaturityTransfer() public {
        bytes32 currentRoot = _mintAndRoot();
        vm.warp(1893456000);

        vm.expectRevert("Bond already matured");
        privateBond.transfer("", currentRoot, [NULL_A, NULL_A_PAD], [COMM_OUT_A, COMM_PAD_A], MATURITY);
    }

    function testTransferInvalidRoot() public {
        bytes32 badRoot = 0xdead0000000000000000000000000000dead0000000000000000000000000000;

        vm.expectRevert("Invalid Merkle Root");
        privateBond.transfer("", badRoot, [NULL_A, NULL_A_PAD], [COMM_OUT_A, COMM_PAD_A], MATURITY);
    }

    function testAtomicSwap() public {
        bytes32 currentRoot = _mintAndRoot();
        bytes32[] memory inputsA = _inputs(currentRoot, NULL_A, NULL_A_PAD, COMM_OUT_A, COMM_PAD_A);
        bytes32[] memory inputsB = _inputs(currentRoot, NULL_B, NULL_B_PAD, COMM_OUT_B, COMM_PAD_B);
        mockVerifier.expectInputs(inputsA);
        mockVerifier.expectInputs(inputsB);

        privateBond.atomicSwap("", inputsA, "", inputsB);

        assertTrue(privateBond.nullifiers(NULL_A));
        assertTrue(privateBond.nullifiers(NULL_A_PAD));
        assertTrue(privateBond.nullifiers(NULL_B));
        assertTrue(privateBond.nullifiers(NULL_B_PAD));
        assertEq(privateBond.commitments(1), COMM_OUT_A);
        assertEq(privateBond.commitments(2), COMM_PAD_A);
        assertEq(privateBond.commitments(3), COMM_OUT_B);
        assertEq(privateBond.commitments(4), COMM_PAD_B);
    }

    function testPreventDoubleSpend() public {
        bytes32 currentRoot = _mintAndRoot();
        bytes32[] memory inputsA = _inputs(currentRoot, NULL_A, NULL_A_PAD, COMM_OUT_A, COMM_PAD_A);
        bytes32[] memory inputsB = _inputs(currentRoot, NULL_B, NULL_B_PAD, COMM_OUT_B, COMM_PAD_B);

        privateBond.atomicSwap("", inputsA, "", inputsB);
        vm.expectRevert("Note A already spent");
        privateBond.atomicSwap("", inputsA, "", inputsB);
    }

    // A note spent in a swap leg's second input slot cannot be spent again
    function testSwapRejectsSpentSecondInput() public {
        bytes32 currentRoot = _mintAndRoot();
        privateBond.atomicSwap(
            "",
            _inputs(currentRoot, NULL_A, NULL_A_PAD, COMM_OUT_A, COMM_PAD_A),
            "",
            _inputs(currentRoot, NULL_B, NULL_B_PAD, COMM_OUT_B, COMM_PAD_B)
        );

        bytes32[] memory inputsA = _inputs(currentRoot, keccak256("NULL_A_NEW"), NULL_A_PAD, COMM_OUT_A, COMM_PAD_A);
        bytes32[] memory inputsB =
            _inputs(currentRoot, keccak256("NULL_B_NEW"), keccak256("NULL_B_PAD_NEW"), COMM_OUT_B, COMM_PAD_B);
        vm.expectRevert("Note A already spent");
        privateBond.atomicSwap("", inputsA, "", inputsB);
    }

    function testPreventPostMaturityTrade() public {
        bytes32 currentRoot = _mintAndRoot();
        vm.warp(1893456000 + 1 days);
        bytes32[] memory inputsA = _inputs(currentRoot, NULL_A, NULL_A_PAD, COMM_OUT_A, COMM_PAD_A);
        bytes32[] memory inputsB = _inputs(currentRoot, NULL_B, NULL_B_PAD, COMM_OUT_B, COMM_PAD_B);

        vm.expectRevert("Bond A already matured");
        privateBond.atomicSwap("", inputsA, "", inputsB);
    }

    function testSwapRejectsRedemptionLeg() public {
        bytes32 currentRoot = _mintAndRoot();
        bytes32[] memory inputsA = _inputs(currentRoot, NULL_A, NULL_A_PAD, COMM_OUT_A, COMM_PAD_A);
        bytes32[] memory inputsB = _inputs(currentRoot, NULL_B, NULL_B_PAD, COMM_OUT_B, COMM_PAD_B);
        inputsA[BondPublicInputs.IS_REDEEM] = bytes32(uint256(1));

        vm.expectRevert("Swap leg A is a redemption");
        privateBond.atomicSwap("", inputsA, "", inputsB);
    }

    function testSwapRejectsWrongInputCount() public {
        bytes32 currentRoot = _mintAndRoot();
        bytes32[] memory inputsA = new bytes32[](4);
        inputsA[0] = currentRoot;
        inputsA[1] = NULL_A;
        inputsA[2] = COMM_OUT_A;
        inputsA[3] = MATURITY;
        bytes32[] memory inputsB = _inputs(currentRoot, NULL_B, NULL_B_PAD, COMM_OUT_B, COMM_PAD_B);

        vm.expectRevert("Wrong public input count");
        privateBond.atomicSwap("", inputsA, "", inputsB);
    }

    function testBurnAtMaturity() public {
        bytes32 currentRoot = _mintAndRoot();
        vm.warp(1893456000);

        bytes32[] memory expected = _inputs(currentRoot, NULL_A, NULL_A_PAD, bytes32(0), bytes32(0));
        expected[BondPublicInputs.IS_REDEEM] = bytes32(uint256(1));
        mockVerifier.expectInputs(expected);

        bytes32[2] memory nullsIn = [NULL_A, NULL_A_PAD];
        bytes32[2] memory commsOut = [bytes32(0), bytes32(0)];
        privateBond.burn("", currentRoot, nullsIn, commsOut, MATURITY);

        assertTrue(privateBond.nullifiers(NULL_A));
        assertTrue(privateBond.nullifiers(NULL_A_PAD));
    }

    function testPreventEarlyRedemption() public {
        privateBond.mint(0x1de409fb2319657514027650e41731fc3c5b77448fdd2b9aceeda9cf95c499e7);
        bytes32 currentRoot = privateBond.buildMerkleRoot();
        vm.warp(1893456000 - 365 days);

        bytes32[2] memory nullsIn = [NULL_A, NULL_B];
        bytes32[2] memory commsOut = [bytes32(0), bytes32(0)];
        vm.expectRevert("Bond not at maturity yet");
        privateBond.burn("", currentRoot, nullsIn, commsOut, MATURITY);
    }

    function testPreventDoubleRedemption() public {
        privateBond.mint(0x1de409fb2319657514027650e41731fc3c5b77448fdd2b9aceeda9cf95c499e7);
        bytes32 currentRoot = privateBond.buildMerkleRoot();
        vm.warp(1893456000);

        bytes32[2] memory nullsIn = [NULL_A, NULL_B];
        bytes32[2] memory commsOut = [bytes32(0), bytes32(0)];
        privateBond.burn("", currentRoot, nullsIn, commsOut, MATURITY);
        vm.expectRevert("Note 0 already spent");
        privateBond.burn("", currentRoot, nullsIn, commsOut, MATURITY);
    }

    function testInvalidRoot() public {
        bytes32 badRoot = 0xdead0000000000000000000000000000dead0000000000000000000000000000;
        bytes32[2] memory nullsIn = [NULL_A, NULL_B];
        bytes32[2] memory commsOut = [bytes32(0), bytes32(0)];
        vm.expectRevert("Invalid Merkle Root");
        privateBond.burn("", badRoot, nullsIn, commsOut, MATURITY);
    }

    function testOnlyOwnerCanSwap() public {
        address attacker = address(0xDEAD);
        bytes32[] memory inputs = new bytes32[](BondPublicInputs.LENGTH);

        vm.prank(attacker);
        vm.expectRevert(abi.encodeWithSignature("OwnableUnauthorizedAccount(address)", attacker));
        privateBond.atomicSwap("", inputs, "", inputs);
    }

    function testIdenticalNullifiers() public {
        bytes32 currentRoot = _mintAndRoot();
        bytes32[] memory inputsA = _inputs(currentRoot, NULL_A, NULL_A_PAD, COMM_OUT_A, COMM_PAD_A);

        // Same first input in both legs
        bytes32[] memory inputsB = _inputs(currentRoot, NULL_A, NULL_B_PAD, COMM_OUT_B, COMM_PAD_B);
        vm.expectRevert("Identical nullifiers");
        privateBond.atomicSwap("", inputsA, "", inputsB);

        // Same second input in both legs
        inputsB = _inputs(currentRoot, NULL_B, NULL_A_PAD, COMM_OUT_B, COMM_PAD_B);
        vm.expectRevert("Identical nullifiers");
        privateBond.atomicSwap("", inputsA, "", inputsB);
    }
}
