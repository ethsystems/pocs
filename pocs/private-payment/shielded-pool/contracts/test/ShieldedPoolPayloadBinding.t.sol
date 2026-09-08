// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {IVerifier} from "../src/interfaces/IVerifier.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";

/// @dev Verifier that accepts a proof only when the public inputs have the expected length and
/// the last one equals an expected value. Stands in for a real verifier whose proof was made
/// over a specific payload commitment.
contract ExpectingVerifier is IVerifier {
    uint256 public expectedLength;
    bytes32 public expectedLast;

    function expect(uint256 length, bytes32 last) external {
        expectedLength = length;
        expectedLast = last;
    }

    function _check(bytes32[] calldata inputs) internal view returns (bool) {
        return inputs.length == expectedLength && inputs[inputs.length - 1] == expectedLast;
    }

    function verifyDeposit(bytes calldata, bytes32[] calldata inputs) external view override returns (bool) {
        return _check(inputs);
    }

    function verifyTransfer(bytes calldata, bytes32[] calldata inputs) external view override returns (bool) {
        return _check(inputs);
    }

    function verifyWithdraw(bytes calldata, bytes32[] calldata inputs) external view override returns (bool) {
        return _check(inputs);
    }
}

/// @title Payload-commitment binding (spec 2/SHIELDED-POOL 4.6)
/// @notice The pool derives the payload commitment from the bytes actually submitted and passes
/// it to the verifier as the last public input. A relayer that garbles the payload therefore
/// presents a different public input than the one the prover committed to, and the proof fails.
contract ShieldedPoolPayloadBindingTest is Test {
    uint256 internal constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    ShieldedPool internal pool;
    ExpectingVerifier internal verifier;
    MockERC20 internal token;

    address internal user = address(0x1);
    uint256 internal constant AMOUNT = 1000e6;

    function setUp() public {
        AttestationRegistry registry = new AttestationRegistry();
        verifier = new ExpectingVerifier();
        pool = new ShieldedPool(address(verifier), address(registry));

        token = new MockERC20("USD Coin", "USDC", 6);
        pool.addSupportedToken(address(token));
        token.mint(user, AMOUNT * 10);
        vm.prank(user);
        token.approve(address(pool), type(uint256).max);
    }

    function _deposit(bytes32 commitment, bytes memory payload) internal {
        vm.prank(user);
        pool.deposit("", commitment, address(token), AMOUNT, user, payload);
    }

    function test_payloadCommitment_isKeccakModP() public view {
        bytes memory payload = hex"deadbeef";
        assertEq(uint256(pool.payloadCommitment(payload)), uint256(keccak256(payload)) % P);
        assertLt(uint256(pool.payloadCommitment(payload)), P, "must be a canonical field element");
        assertEq(uint256(pool.payloadCommitment("")), uint256(keccak256("")) % P);
    }

    function test_deposit_bindsPayloadAsSixthInput() public {
        bytes memory payload = "encrypted note bytes";
        verifier.expect(6, pool.payloadCommitment(payload));
        _deposit(bytes32(uint256(1)), payload);
        assertEq(pool.getCommitmentCount(), 1);
    }

    function test_deposit_garbledPayloadFailsProof() public {
        verifier.expect(6, pool.payloadCommitment("original"));
        vm.expectRevert(ShieldedPool.InvalidProof.selector);
        _deposit(bytes32(uint256(1)), "garbled!");
    }

    function test_transfer_bindsPayloadAsSixthInput() public {
        verifier.expect(6, pool.payloadCommitment(""));
        _deposit(bytes32(uint256(1)), "");
        bytes32 root = pool.commitmentRoot();

        bytes memory payload = "two encrypted notes";
        bytes32[2] memory nullifiers_ = [bytes32(uint256(11)), bytes32(uint256(12))];
        bytes32[2] memory commitments_ = [bytes32(uint256(21)), bytes32(uint256(22))];

        verifier.expect(6, pool.payloadCommitment("something else"));
        vm.expectRevert(ShieldedPool.InvalidProof.selector);
        pool.transfer("", nullifiers_, commitments_, root, payload);

        verifier.expect(6, pool.payloadCommitment(payload));
        pool.transfer("", nullifiers_, commitments_, root, payload);
        assertEq(pool.getCommitmentCount(), 3);
    }
}
