// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {PoseidonT6} from "poseidon-solidity/PoseidonT6.sol";
import {IAccessControl} from "@openzeppelin-contracts/access/IAccessControl.sol";
import {PublicInputs} from "../src/PublicInputs.sol";

contract AttestationRegistryTest is Test {
    AttestationRegistry public registry;

    uint256 constant EPOCH_SECONDS = 86400;
    uint256 constant MAX_ATTESTATION_EPOCHS = 30;
    uint256 constant OVERLAP_EPOCHS = 3;
    uint256 constant MIN_BATCH = 2;

    address internal agent = address(0xA6E7);
    address internal timelock = address(0x71);

    function setUp() public {
        vm.warp(1000 * EPOCH_SECONDS);
        registry =
            new AttestationRegistry(EPOCH_SECONDS, MAX_ATTESTATION_EPOCHS, OVERLAP_EPOCHS, MIN_BATCH, agent, timelock);
    }

    function _owners(uint256 n, uint256 start) internal pure returns (bytes32[] memory owners) {
        owners = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            owners[i] = bytes32(start + i);
        }
    }

    function _periodEnd() internal view returns (uint64) {
        return uint64((registry.currentEpoch() + MAX_ATTESTATION_EPOCHS) * EPOCH_SECONDS);
    }

    function testLeafHashesItsFieldsInTheCircuitsOrder() public {
        bytes32[] memory owners = _owners(2, 0x0e1);
        uint64 expiresAt = _periodEnd();
        vm.prank(agent);
        registry.addAttestations(owners, expiresAt, 0);

        // attestation_leaf = Poseidon1(owner, attester, generation, issued_at, expires_at)
        uint256 leaf0 =
            PoseidonT6.hash([uint256(owners[0]), uint256(uint160(agent)), 0, block.timestamp, uint256(expiresAt)]);
        uint256 leaf1 =
            PoseidonT6.hash([uint256(owners[1]), uint256(uint160(agent)), 0, block.timestamp, uint256(expiresAt)]);
        // A two-leaf LeanIMT's root is Poseidon1(leaf0, leaf1).
        assertEq(uint256(registry.attestationRoot()), _hash2(leaf0, leaf1));
        assertEq(registry.getAttestationCount(), 2);
    }

    /// @dev The known answer the circuits' `test_known_answer_leaf` also pins:
    ///      the agent attests owner 0x0e1 at epoch 1000 until epoch 1030. It
    ///      fixes the leaf's field order, which a change on both sides at once
    ///      would leave every other test passing.
    function testLeafMatchesTheCircuitsKnownAnswer() public {
        bytes32[] memory owners = _owners(2, 0x0e1);
        uint64 expiresAt = _periodEnd();
        assertEq(registry.currentEpoch(), 1000);
        assertEq(expiresAt, 1030 * EPOCH_SECONDS);
        vm.expectEmit(address(registry));
        emit AttestationRegistry.AttestationAdded(
            0x063a450b852c613c5446bb5185c94f06f4b20628601388b87462d939b7013332,
            owners[0],
            agent,
            0,
            uint64(block.timestamp),
            expiresAt
        );
        vm.prank(agent);
        registry.addAttestations(owners, expiresAt, 0);
    }

    function _hash2(uint256 a, uint256 b) internal pure returns (uint256) {
        return PoseidonT3Wrapper.hash(a, b);
    }

    function testOnlyTheAttesterAttests() public {
        bytes32[] memory owners = _owners(2, 1);
        uint64 expiresAt = _periodEnd();
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, address(this), registry.ATTESTER_ROLE()
            )
        );
        registry.addAttestations(owners, expiresAt, 0);
    }

    function testBatchBelowMinimumReverts() public {
        bytes32[] memory owners = _owners(1, 1);
        uint64 expiresAt = _periodEnd();
        vm.prank(agent);
        vm.expectRevert(AttestationRegistry.BatchTooSmall.selector);
        registry.addAttestations(owners, expiresAt, 0);
    }

    function testExpiryMustCoverTheCurrentEpoch() public {
        bytes32[] memory owners = _owners(2, 1);
        uint64 tooSoon = uint64((registry.currentEpoch() + 1) * EPOCH_SECONDS - 1);
        vm.prank(agent);
        vm.expectRevert(AttestationRegistry.ExpiryOutOfInterval.selector);
        registry.addAttestations(owners, tooSoon, 0);
    }

    /// @dev The ceiling bounds the revocation delay: issued in epoch e, an
    ///      attestation is usable through epoch e + 32 at most, i.e. 33 epochs.
    function testExpiryCeilingBoundsTheRevocationDelay() public {
        bytes32[] memory owners = _owners(2, 1);
        uint256 e = registry.currentEpoch();
        uint64 ceiling = uint64((e + 1 + MAX_ATTESTATION_EPOCHS + OVERLAP_EPOCHS) * EPOCH_SECONDS);

        vm.prank(agent);
        vm.expectRevert(AttestationRegistry.ExpiryOutOfInterval.selector);
        registry.addAttestations(owners, ceiling, 0);

        vm.prank(agent);
        registry.addAttestations(owners, ceiling - 1, 0);

        // The circuit accepts epoch t only if (t + 1) * E <= expires_at.
        uint256 lastUsable = (uint256(ceiling - 1) / EPOCH_SECONDS) - 1;
        assertEq(lastUsable, e + 32);
    }

    function testGenerationMayOnlyStayOrStepByOne() public {
        bytes32[] memory owners = _owners(2, 1);
        uint64 expiresAt = _periodEnd();
        vm.startPrank(agent);
        vm.expectRevert(AttestationRegistry.WrongGeneration.selector);
        registry.addAttestations(owners, expiresAt, 2);
        registry.addAttestations(owners, expiresAt, 1);
        assertEq(registry.currentGeneration(), 1);
        vm.expectRevert(AttestationRegistry.WrongGeneration.selector);
        registry.addAttestations(owners, expiresAt, 0);
        vm.stopPrank();
    }

    /// @dev Poseidon reduces its inputs, so `owner + p` would make the same leaf
    ///      as `owner` while every client reading the event rejects the value.
    function testANonCanonicalOwnerIsRefused() public {
        bytes32[] memory owners = _owners(2, 1);
        owners[1] = bytes32(PublicInputs.BN254_MODULUS + 1);
        uint64 expiresAt = _periodEnd();
        vm.prank(agent);
        vm.expectRevert(AttestationRegistry.NonCanonicalOwner.selector);
        registry.addAttestations(owners, expiresAt, 0);
    }

    /// @dev The size is set directly: filling 2^20 leaves is not what is tested.
    ///      The tree's size is the first word of its storage (slot 1).
    function testTheRegistryStopsAtTheCircuitsTreeCapacity() public {
        uint256 cap = registry.MAX_ATTESTATIONS();
        uint64 expiresAt = _periodEnd();
        vm.store(address(registry), bytes32(uint256(1)), bytes32(cap - 1));
        vm.store(address(registry), bytes32(uint256(2)), bytes32(uint256(20)));
        vm.prank(agent);
        vm.expectRevert(AttestationRegistry.RegistryFull.selector);
        registry.addAttestations(_owners(2, 1), expiresAt, 0);

        vm.store(address(registry), bytes32(uint256(1)), bytes32(cap - 2));
        vm.prank(agent);
        registry.addAttestations(_owners(2, 1), expiresAt, 0);
        assertEq(registry.getAttestationCount(), cap);
    }

    function testOldRootsStayKnown() public {
        bytes32[] memory owners = _owners(2, 1);
        uint64 expiresAt = _periodEnd();
        vm.prank(agent);
        registry.addAttestations(owners, expiresAt, 0);
        bytes32 first = registry.attestationRoot();
        vm.prank(agent);
        registry.addAttestations(_owners(2, 10), expiresAt, 0);
        assertTrue(registry.isKnownAttestationRoot(first));
        assertTrue(registry.isKnownAttestationRoot(registry.attestationRoot()));
        assertFalse(registry.isKnownAttestationRoot(bytes32(uint256(0xbad))));
    }

    /// @dev Each batch stores the root before it: the second stores `first`,
    ///      and 300 more evict it, while `second` is still in the ring.
    function testARootLeavesTheRingAfterMaxHistoricalRoots() public {
        uint64 expiresAt = _periodEnd();
        vm.startPrank(agent);
        registry.addAttestations(_owners(2, 1), expiresAt, 0);
        bytes32 first = registry.attestationRoot();
        registry.addAttestations(_owners(2, 3), expiresAt, 0);
        bytes32 second = registry.attestationRoot();
        // 300 batches exceed one test's gas limit; the eviction, not the gas, is under test.
        vm.pauseGasMetering();
        for (uint256 i = 0; i < registry.MAX_HISTORICAL_ROOTS(); i++) {
            registry.addAttestations(_owners(2, 10 + 2 * i), expiresAt, 0);
        }
        vm.stopPrank();
        assertFalse(registry.isKnownAttestationRoot(first));
        assertTrue(registry.isKnownAttestationRoot(second));
    }

    function testSetAttesterIsTimelockedAndMovesTheRole() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, address(this), registry.TIMELOCK_ROLE()
            )
        );
        registry.setAttester(address(0xB0B));

        vm.prank(timelock);
        registry.setAttester(address(0xB0B));
        assertEq(registry.attester(), address(0xB0B));
        assertFalse(registry.hasRole(registry.ATTESTER_ROLE(), agent));
        assertTrue(registry.hasRole(registry.ATTESTER_ROLE(), address(0xB0B)));
    }

    function testTimelockCanHandOverItsRole() public {
        address next = address(0x7172);
        bytes32 role = registry.TIMELOCK_ROLE();
        vm.prank(timelock);
        registry.grantRole(role, next);
        vm.prank(timelock);
        registry.renounceRole(role, timelock);

        vm.prank(next);
        registry.setAttester(address(0xB0B));
        assertEq(registry.attester(), address(0xB0B));
        assertFalse(registry.hasRole(role, timelock));
    }

    function testRaisingTheGenerationFloorRetiresOldLeavesAtActivation() public {
        uint256 activation = registry.currentEpoch() + 5;
        vm.prank(timelock);
        registry.raiseMinAcceptedGeneration(1, activation);
        assertEq(registry.minAcceptedGeneration(), 0);
        vm.warp(activation * EPOCH_SECONDS);
        assertEq(registry.minAcceptedGeneration(), 1);
    }

    /// @dev A second raise first commits the first one if it is already active;
    ///      otherwise the floor would drop back to the old value until the
    ///      second activates.
    function testASecondRaiseKeepsTheFirstInForce() public {
        uint256 epoch = registry.currentEpoch();
        vm.prank(timelock);
        registry.raiseMinAcceptedGeneration(1, epoch + 1);
        vm.warp((epoch + 1) * EPOCH_SECONDS);
        assertEq(registry.minAcceptedGeneration(), 1);

        vm.prank(timelock);
        registry.raiseMinAcceptedGeneration(2, epoch + 5);
        assertEq(registry.minAcceptedGeneration(), 1, "the first raise stays in force");
        vm.warp((epoch + 5) * EPOCH_SECONDS);
        assertEq(registry.minAcceptedGeneration(), 2);
    }

    /// @dev A floor above every issued generation retires every attestation,
    ///      which stops every deposit, transfer and withdrawal.
    function testOnlyGovernanceRaisesTheGenerationFloor() public {
        bytes32 role = registry.TIMELOCK_ROLE();
        uint256 activation = registry.currentEpoch() + 1;
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, agent, role));
        vm.prank(agent);
        registry.raiseMinAcceptedGeneration(1, activation);
    }

    function testGenerationFloorRequiresAFutureActivationAndAnIncrease() public {
        uint256 epoch = registry.currentEpoch();
        vm.startPrank(timelock);
        vm.expectRevert(AttestationRegistry.ActivationNotFuture.selector);
        registry.raiseMinAcceptedGeneration(1, epoch);
        vm.expectRevert(AttestationRegistry.GenerationNotIncreasing.selector);
        registry.raiseMinAcceptedGeneration(0, epoch + 1);
        vm.stopPrank();
    }

    // ========== Replacing the attester ==========

    address internal successor = address(0xB0B);

    /// @dev A planned replacement: the outgoing attester's leaves stay valid until
    ///      they lapse, and the successor renews them at the same generation.
    function testAPlannedReplacementRetiresNoLeaf() public {
        uint64 expiresAt = _periodEnd();
        vm.prank(agent);
        registry.addAttestations(_owners(2, 1), expiresAt, 0);
        vm.prank(timelock);
        registry.setAttester(successor);

        vm.warp((registry.currentEpoch() + 5) * EPOCH_SECONDS);
        assertEq(registry.minAcceptedGeneration(), 0);
        vm.prank(successor);
        registry.addAttestations(_owners(2, 3), expiresAt, 0);
    }

    /// @dev A lost key, or an agent leaving without a successor: nothing issued
    ///      after `trustedUntil`, so every leaf stays valid, and the agent can
    ///      attest no more.
    function testRevokingWithNothingIssuedSinceRetiresNoLeaf() public {
        uint64 expiresAt = _periodEnd();
        vm.prank(agent);
        registry.addAttestations(_owners(2, 1), expiresAt, 0);
        uint64 issuedAt = registry.lastIssuedAt();
        assertEq(issuedAt, block.timestamp);
        vm.warp(block.timestamp + 100);

        vm.expectEmit(address(registry));
        emit AttestationRegistry.AttesterRevoked(agent, false);
        vm.prank(timelock);
        registry.revokeAttester(issuedAt);

        assertEq(registry.attester(), address(0));
        bytes32 role = registry.ATTESTER_ROLE();
        assertFalse(registry.hasRole(role, agent));
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, agent, role));
        vm.prank(agent);
        registry.addAttestations(_owners(2, 3), expiresAt, 0);

        vm.warp((registry.currentEpoch() + 5) * EPOCH_SECONDS);
        assertEq(registry.minAcceptedGeneration(), 0, "no leaf retired");
    }

    /// @dev A stolen key with bogus leaves already issued: `trustedUntil` before
    ///      them retires every leaf, honest ones too, from the next epoch.
    function testRevokingAfterAnIssuanceRetiresEveryLeafFromTheNextEpoch() public {
        uint64 expiresAt = _periodEnd();
        uint64 trustedUntil = uint64(block.timestamp);
        vm.warp(block.timestamp + 100);
        vm.prank(agent);
        registry.addAttestations(_owners(2, 1), expiresAt, 0);

        uint256 epoch = registry.currentEpoch();
        vm.expectEmit(address(registry));
        emit AttestationRegistry.AttesterRevoked(agent, true);
        vm.prank(timelock);
        registry.revokeAttester(trustedUntil);
        assertEq(registry.minAcceptedGeneration(), 0, "in force until the next epoch");
        vm.warp((epoch + 1) * EPOCH_SECONDS);
        assertEq(registry.minAcceptedGeneration(), 1);
    }

    /// @dev The attester sees the revocation queued and attests past any floor
    ///      governance could have named in it, each batch stepping the generation
    ///      by one. The floor is read when the revocation executes, so those
    ///      leaves are retired too.
    function testAnAttesterCannotOutrunItsRevocation() public {
        uint64 trustedUntil = uint64(block.timestamp);
        vm.warp(block.timestamp + 100);
        uint64 expiresAt = _periodEnd();
        vm.startPrank(agent);
        registry.addAttestations(_owners(2, 1), expiresAt, 1);
        registry.addAttestations(_owners(2, 3), expiresAt, 2);
        vm.stopPrank();
        assertEq(registry.currentGeneration(), 2);

        uint256 epoch = registry.currentEpoch();
        vm.prank(timelock);
        registry.revokeAttester(trustedUntil);
        vm.warp((epoch + 1) * EPOCH_SECONDS);
        assertEq(registry.minAcceptedGeneration(), 3, "past every generation issued");
    }

    /// @dev A stolen key with a successor ready, both calls in one timelock
    ///      batch: the successor attests at the new floor before it activates,
    ///      so holders it renews in time see no gap.
    function testASuccessorAttestsAtTheNewFloorBeforeItActivates() public {
        uint64 expiresAt = _periodEnd();
        vm.prank(agent);
        registry.addAttestations(_owners(2, 1), expiresAt, 0);
        uint256 epoch = registry.currentEpoch();
        vm.startPrank(timelock);
        registry.revokeAttester(0);
        registry.setAttester(successor);
        vm.stopPrank();

        vm.prank(successor);
        registry.addAttestations(_owners(2, 1), expiresAt, 1);
        vm.warp((epoch + 1) * EPOCH_SECONDS);
        assertEq(registry.minAcceptedGeneration(), 1, "the successor's leaves sit at the floor");
    }

    /// @dev A floor governance raised earlier stays when a revocation needs less.
    function testARevocationNeverLowersTheFloor() public {
        uint64 expiresAt = _periodEnd();
        uint256 epoch = registry.currentEpoch();
        vm.prank(timelock);
        registry.raiseMinAcceptedGeneration(2, epoch + 1);
        vm.warp((epoch + 1) * EPOCH_SECONDS);
        vm.prank(agent);
        registry.addAttestations(_owners(2, 1), expiresAt, 0);

        vm.prank(timelock);
        registry.revokeAttester(0);
        vm.warp((epoch + 2) * EPOCH_SECONDS);
        assertEq(registry.minAcceptedGeneration(), 2);
    }

    function testRevokeAttesterGuards() public {
        bytes32 role = registry.TIMELOCK_ROLE();
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, agent, role));
        vm.prank(agent);
        registry.revokeAttester(0);

        vm.startPrank(timelock);
        vm.expectRevert(AttestationRegistry.TrustedUntilInFuture.selector);
        registry.revokeAttester(uint64(block.timestamp + 1));
        registry.revokeAttester(uint64(block.timestamp));
        vm.expectRevert(AttestationRegistry.NoAttester.selector);
        registry.revokeAttester(uint64(block.timestamp));
        vm.stopPrank();
    }

    function testConstructorValidation() public {
        vm.expectRevert(AttestationRegistry.OverlapTooLarge.selector);
        new AttestationRegistry(EPOCH_SECONDS, 3, 3, 1, agent, timelock);
        vm.expectRevert(AttestationRegistry.MinBatchSizeZero.selector);
        new AttestationRegistry(EPOCH_SECONDS, 30, 3, 0, agent, timelock);
        vm.expectRevert(AttestationRegistry.ZeroAddress.selector);
        new AttestationRegistry(EPOCH_SECONDS, 30, 3, 1, address(0), timelock);
    }
}

library PoseidonT3Wrapper {
    function hash(uint256 a, uint256 b) internal pure returns (uint256) {
        return PoseidonT3.hash([a, b]);
    }
}

import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";
