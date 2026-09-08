// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {ShieldedPool} from "../src/ShieldedPool.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {MockVerifier} from "../src/mocks/MockCompositeVerifier.sol";
import {MockERC20} from "../src/mocks/MockERC20.sol";

/// @title Field-modulus range check — defense-in-depth regression tests
/// @notice Audit finding: shieldedpool-missing-field-modulus-range-check (Critical).
///
/// These tests use a MockVerifier that ACCEPTS EVERYTHING. They prove the pool rejects a
/// non-canonical nullifier `N + P` on its own — independent of what the verifier does — so the
/// guarantee survives a verifier swapped in via setVerifier that lacks the check. The companion
/// WithdrawVerifierAliasing.t.sol proves the generated verifier also rejects it; this proves the
/// pool does not depend on that.
contract ShieldedPoolFieldModulusTest is Test {
    /// BN254 scalar field modulus (== ShieldedPool.P_BN254, which is internal).
    uint256 internal constant P = 21888242871839275222246405745257275088548364400416034343698204186575808495617;

    ShieldedPool internal pool;
    AttestationRegistry internal registry;
    MockVerifier internal verifier;
    MockERC20 internal token;

    address internal user = address(0x1);
    address internal recipient = address(0x2);
    uint256 internal constant AMOUNT = 1000e6;

    function setUp() public {
        registry = new AttestationRegistry();
        verifier = new MockVerifier(); // accepts all proofs by default
        pool = new ShieldedPool(address(verifier), address(registry));

        token = new MockERC20("USD Coin", "USDC", 6);
        pool.addSupportedToken(address(token));
        token.mint(user, AMOUNT * 10);
        vm.prank(user);
        token.approve(address(pool), type(uint256).max);
    }

    /// Populate the tree and fund the pool; return a root the pool will accept.
    function _seedPoolAndGetRoot() internal returns (bytes32 root) {
        vm.prank(user);
        pool.deposit("", bytes32(uint256(1)), address(token), AMOUNT, user, "");
        return pool.commitmentRoot();
    }

    /// Sanity: `N` and `N + P` are distinct bytes32 but the same field element.
    function test_aliasPrecondition() public pure {
        uint256 n = 101;
        uint256 alias_ = n + P;
        assertTrue(bytes32(alias_) != bytes32(n), "raw bytes must differ");
        assertEq(alias_ % P, n, "must reduce to the same field element");
    }

    /// Withdraw with a non-canonical nullifier reverts in the POOL, even though the
    /// mock verifier would accept the proof.
    function test_withdraw_rejectsNonCanonicalNullifier() public {
        bytes32 root = _seedPoolAndGetRoot();
        bytes32 aliasedNullifier = bytes32(uint256(101) + P);

        assertTrue(verifier.withdrawResult(), "mock verifier accepts all, isolating the pool check");
        vm.expectRevert(ShieldedPool.PublicInputGeFieldModulus.selector);
        pool.withdraw("", aliasedNullifier, address(token), AMOUNT, recipient, root);
    }

    /// Variant B linchpin: same note in both transfer input slots as `n0 = N`, `n1 = N + P`.
    /// The raw-bytes IdenticalNullifiers guard passes (distinct bytes32); the pool's canonical
    /// check must still reject `n1`.
    function test_transfer_rejectsAliasedSecondNullifier() public {
        bytes32 root = _seedPoolAndGetRoot();
        bytes32 n0 = bytes32(uint256(100));
        bytes32 n1 = bytes32(uint256(100) + P); // aliases n0 inside the proof, distinct here

        assertTrue(n0 != n1, "IdenticalNullifiers guard would pass");
        bytes32[2] memory nullifiers = [n0, n1];
        bytes32[2] memory outputs = [bytes32(uint256(2)), bytes32(uint256(3))];

        vm.expectRevert(ShieldedPool.PublicInputGeFieldModulus.selector);
        pool.transfer("", nullifiers, outputs, root, "");
    }

    /// Amounts at or above 2^128 are rejected (spec §5.3).
    function test_withdraw_rejectsAmountGe2Pow128() public {
        vm.expectRevert(ShieldedPool.AmountTooLarge.selector);
        pool.withdraw("", bytes32(uint256(101)), address(token), 1 << 128, recipient, bytes32(0));
    }

    function test_deposit_rejectsAmountGe2Pow128() public {
        vm.prank(user);
        vm.expectRevert(ShieldedPool.AmountTooLarge.selector);
        pool.deposit("", bytes32(uint256(1)), address(token), 1 << 128, user, "");
    }

    /// Happy path is unaffected: a canonical nullifier still withdraws successfully.
    function test_withdraw_canonicalNullifierStillWorks() public {
        bytes32 root = _seedPoolAndGetRoot();
        uint256 recipientBefore = token.balanceOf(recipient);

        pool.withdraw("", bytes32(uint256(101)), address(token), AMOUNT, recipient, root);

        assertTrue(pool.nullifiers(bytes32(uint256(101))));
        assertEq(token.balanceOf(recipient), recipientBefore + AMOUNT);
    }
}
