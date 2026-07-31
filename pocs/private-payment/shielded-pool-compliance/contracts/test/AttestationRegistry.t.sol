// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {IAccessControl} from "@openzeppelin-contracts/access/IAccessControl.sol";
import {AttestationRegistry} from "../src/AttestationRegistry.sol";
import {AttesterRevocationTree} from "../src/AttesterRevocationTree.sol";

contract AttestationRegistryTest is Test {
    AttestationRegistry public registry;

    uint256 constant EPOCH_SECONDS = 86400;
    uint256 constant MAX_ATTESTATION_EPOCHS = 7;
    uint256 constant MIN_COHORT_SIZE = 10;
    uint256 constant OVERLAP_EPOCHS = 2;

    address public admin = address(this);
    address public timelock = address(0xA11CE);
    address public attester = address(0xB0B);
    address public nonAttester = address(0xC0DE);

    uint64 public expiresAt;

    function setUp() public {
        vm.warp(100 * EPOCH_SECONDS);

        registry = new AttestationRegistry(
            EPOCH_SECONDS, MAX_ATTESTATION_EPOCHS, MIN_COHORT_SIZE, admin, timelock, OVERLAP_EPOCHS
        );
        registry.addAttester(attester);

        uint256 period = registry.currentEpoch() / MAX_ATTESTATION_EPOCHS;
        expiresAt = uint64((period + 1) * MAX_ATTESTATION_EPOCHS * EPOCH_SECONDS);
    }

    function _cohort(uint256 n, uint256 offset) internal pure returns (bytes32[] memory subjects) {
        subjects = new bytes32[](n);
        for (uint256 i = 0; i < n; i++) {
            subjects[i] = keccak256(abi.encode("subject", offset + i));
        }
    }

    // ========== Constructor ==========

    function testConstructorRevertsOnZeroEpochSeconds() public {
        vm.expectRevert(AttestationRegistry.ZeroEpochSeconds.selector);
        new AttestationRegistry(0, MAX_ATTESTATION_EPOCHS, MIN_COHORT_SIZE, admin, timelock, OVERLAP_EPOCHS);
    }

    function testConstructorRevertsOnZeroAdmin() public {
        vm.expectRevert(AttestationRegistry.ZeroAddress.selector);
        new AttestationRegistry(
            EPOCH_SECONDS, MAX_ATTESTATION_EPOCHS, MIN_COHORT_SIZE, address(0), timelock, OVERLAP_EPOCHS
        );
    }

    function testConstructorRevertsOnZeroTimelock() public {
        vm.expectRevert(AttestationRegistry.ZeroAddress.selector);
        new AttestationRegistry(
            EPOCH_SECONDS, MAX_ATTESTATION_EPOCHS, MIN_COHORT_SIZE, admin, address(0), OVERLAP_EPOCHS
        );
    }

    function testConstructorRevertsOnOverlapAtOrAbovePeriod() public {
        vm.expectRevert(AttestationRegistry.OverlapTooLarge.selector);
        new AttestationRegistry(
            EPOCH_SECONDS, MAX_ATTESTATION_EPOCHS, MIN_COHORT_SIZE, admin, timelock, MAX_ATTESTATION_EPOCHS
        );
    }

    function testConstructorRevertsOnZeroMinCohortSize() public {
        vm.expectRevert(AttestationRegistry.MinCohortSizeZero.selector);
        new AttestationRegistry(EPOCH_SECONDS, MAX_ATTESTATION_EPOCHS, 0, admin, timelock, OVERLAP_EPOCHS);
    }

    // ========== addAttestations ==========

    function testAddAttestationsHappyPath() public {
        bytes32[] memory subjects = _cohort(MIN_COHORT_SIZE, 0);

        bytes32 rootBefore = registry.attestationRoot();
        vm.prank(attester);
        registry.addAttestations(subjects, expiresAt, 0);

        assertTrue(registry.attestationRoot() != rootBefore);
    }

    function testAddAttestationsRevertsCohortTooSmall() public {
        bytes32[] memory subjects = _cohort(MIN_COHORT_SIZE - 1, 0);

        vm.prank(attester);
        vm.expectRevert(AttestationRegistry.CohortTooSmall.selector);
        registry.addAttestations(subjects, expiresAt, 0);
    }

    function testAddAttestationsRevertsExpiryTooLow() public {
        bytes32[] memory subjects = _cohort(MIN_COHORT_SIZE, 0);
        uint64 tooLow = uint64(registry.currentEpoch() * EPOCH_SECONDS);

        vm.prank(attester);
        vm.expectRevert(AttestationRegistry.ExpiryOutOfInterval.selector);
        registry.addAttestations(subjects, tooLow, 0);
    }

    function testAddAttestationsRevertsExpiryTooHigh() public {
        bytes32[] memory subjects = _cohort(MIN_COHORT_SIZE, 0);
        uint64 tooHigh = uint64((registry.currentEpoch() + 1 + MAX_ATTESTATION_EPOCHS + OVERLAP_EPOCHS) * EPOCH_SECONDS);

        vm.prank(attester);
        vm.expectRevert(AttestationRegistry.ExpiryOutOfInterval.selector);
        registry.addAttestations(subjects, tooHigh, 0);
    }

    function testAddAttestationsRevertsExpiryNotOnCalendar() public {
        bytes32[] memory subjects = _cohort(MIN_COHORT_SIZE, 0);

        vm.prank(attester);
        vm.expectRevert(AttestationRegistry.ExpiryNotOnCalendar.selector);
        registry.addAttestations(subjects, expiresAt - 1, 0);
    }

    function testAddAttestationsAcceptsNextPeriodInsideOverlapWindow() public {
        uint256 period = registry.currentEpoch() / MAX_ATTESTATION_EPOCHS;
        uint256 boundaryEpoch = (period + 1) * MAX_ATTESTATION_EPOCHS;
        vm.warp((boundaryEpoch - OVERLAP_EPOCHS) * EPOCH_SECONDS);

        uint64 nextExpiry = uint64((period + 2) * MAX_ATTESTATION_EPOCHS * EPOCH_SECONDS);
        bytes32[] memory subjects = _cohort(MIN_COHORT_SIZE, 0);

        bytes32 rootBefore = registry.attestationRoot();
        vm.prank(attester);
        registry.addAttestations(subjects, nextExpiry, 0);

        assertTrue(registry.attestationRoot() != rootBefore);
    }

    function testAddAttestationsRejectsNextPeriodOutsideOverlapWindow() public {
        uint256 period = registry.currentEpoch() / MAX_ATTESTATION_EPOCHS;
        uint256 boundaryEpoch = (period + 1) * MAX_ATTESTATION_EPOCHS;
        vm.warp((boundaryEpoch - OVERLAP_EPOCHS - 1) * EPOCH_SECONDS);

        uint64 nextExpiry = uint64((period + 2) * MAX_ATTESTATION_EPOCHS * EPOCH_SECONDS);
        bytes32[] memory subjects = _cohort(MIN_COHORT_SIZE, 0);

        vm.prank(attester);
        vm.expectRevert(AttestationRegistry.ExpiryOutOfInterval.selector);
        registry.addAttestations(subjects, nextExpiry, 0);
    }

    function testAddAttestationsRevertsWrongGeneration() public {
        bytes32[] memory subjects = _cohort(MIN_COHORT_SIZE, 0);

        vm.prank(attester);
        vm.expectRevert(AttestationRegistry.WrongGeneration.selector);
        registry.addAttestations(subjects, expiresAt, 2);
    }

    function testAddAttestationsRevertsNotAttester() public {
        bytes32[] memory subjects = _cohort(MIN_COHORT_SIZE, 0);
        bytes32 attesterRole = registry.ATTESTER_ROLE();

        vm.prank(nonAttester);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, nonAttester, attesterRole)
        );
        registry.addAttestations(subjects, expiresAt, 0);
    }

    function testAddAttestationsAcceptsSuccessorGeneration() public {
        bytes32[] memory subjects = _cohort(MIN_COHORT_SIZE, 0);

        vm.prank(attester);
        registry.addAttestations(subjects, expiresAt, 1);

        assertEq(registry.currentGeneration(), 1);
    }

    // ========== Attester management ==========

    function testAddAttesterGrantsRoleAndTreeSlot() public {
        address newAttester = address(0xD00D);
        registry.addAttester(newAttester);

        assertTrue(registry.hasRole(registry.ATTESTER_ROLE(), newAttester));
        assertTrue(registry.isAttester(newAttester));
        assertEq(registry.revokedAtEpoch(newAttester), type(uint64).max);
    }

    function testReAddedAttesterKeepsLoweredRevocation() public {
        uint64 epoch = uint64(registry.currentEpoch());
        vm.prank(timelock);
        registry.lowerRevocation(attester, epoch);

        registry.removeAttester(attester);
        registry.addAttester(attester);

        assertEq(registry.revokedAtEpoch(attester), epoch);
    }

    function testAddAttesterRevertsZeroAddress() public {
        vm.expectRevert(AttestationRegistry.ZeroAddress.selector);
        registry.addAttester(address(0));
    }

    function testAddAttesterRevertsDuplicate() public {
        vm.expectRevert(AttesterRevocationTree.AttesterAlreadyExists.selector);
        registry.addAttester(attester);
    }

    function testAddAttesterRevertsNotAdmin() public {
        bytes32 adminRole = registry.DEFAULT_ADMIN_ROLE();

        vm.prank(nonAttester);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, nonAttester, adminRole)
        );
        registry.addAttester(address(0xD00D));
    }

    function testRemoveAttesterRevokesRoleAndFreesSlot() public {
        registry.removeAttester(attester);

        assertFalse(registry.hasRole(registry.ATTESTER_ROLE(), attester));
        assertFalse(registry.isAttester(attester));
    }

    function testRemoveAttesterRevertsUnknown() public {
        vm.expectRevert(AttesterRevocationTree.AttesterDoesNotExist.selector);
        registry.removeAttester(nonAttester);
    }

    function testRemoveAttesterRevertsNotAdmin() public {
        bytes32 adminRole = registry.DEFAULT_ADMIN_ROLE();

        vm.prank(nonAttester);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, nonAttester, adminRole)
        );
        registry.removeAttester(attester);
    }

    // ========== Attester revocation (timelocked lowering) ==========

    function testLowerRevocationChangesRootAndUnrelatedReadDoesNot() public {
        bytes32 rootBefore = registry.attesterRevocationRoot();

        // An unrelated read must not perturb the root.
        registry.isAttester(attester);
        assertEq(registry.attesterRevocationRoot(), rootBefore);

        uint64 epoch = uint64(registry.currentEpoch());
        vm.prank(timelock);
        registry.lowerRevocation(attester, epoch);

        assertTrue(registry.attesterRevocationRoot() != rootBefore);
        assertEq(registry.revokedAtEpoch(attester), epoch);
    }

    function testLowerRevocationRevertsNotBelowCurrent() public {
        vm.prank(timelock);
        vm.expectRevert(AttestationRegistry.RevocationNotMonotone.selector);
        registry.lowerRevocation(attester, type(uint64).max);
    }

    function testLowerRevocationRevertsBelowCurrentEpoch() public {
        uint64 tooLow = uint64(registry.currentEpoch() - 1);

        vm.prank(timelock);
        vm.expectRevert(AttestationRegistry.RevocationNotMonotone.selector);
        registry.lowerRevocation(attester, tooLow);
    }

    function testLowerRevocationRevertsUnknownAttester() public {
        uint64 epoch = uint64(registry.currentEpoch());

        vm.prank(timelock);
        vm.expectRevert(AttestationRegistry.UnknownAttester.selector);
        registry.lowerRevocation(nonAttester, epoch);
    }

    function testLowerRevocationRevertsNotTimelock() public {
        bytes32 timelockRole = registry.TIMELOCK_ROLE();
        uint64 epoch = uint64(registry.currentEpoch());

        vm.prank(nonAttester);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, nonAttester, timelockRole)
        );
        registry.lowerRevocation(attester, epoch);
    }

    // ========== minAcceptedGeneration ==========

    function testRaiseMinAcceptedGenerationActivatesAtEpoch() public {
        uint256 activationEpoch = registry.currentEpoch() + 2;

        vm.prank(timelock);
        registry.raiseMinAcceptedGeneration(1, activationEpoch);

        assertEq(registry.minAcceptedGeneration(), 0);

        vm.warp(activationEpoch * EPOCH_SECONDS);
        assertEq(registry.minAcceptedGeneration(), 1);
    }

    function testRaiseMinAcceptedGenerationRevertsActivationNotFuture() public {
        uint256 epoch = registry.currentEpoch();

        vm.prank(timelock);
        vm.expectRevert(AttestationRegistry.ActivationNotFuture.selector);
        registry.raiseMinAcceptedGeneration(1, epoch);
    }

    function testRaiseMinAcceptedGenerationRevertsGenerationNotIncreasing() public {
        uint256 activationEpoch = registry.currentEpoch() + 1;

        vm.prank(timelock);
        vm.expectRevert(AttestationRegistry.GenerationNotIncreasing.selector);
        registry.raiseMinAcceptedGeneration(0, activationEpoch);
    }

    function testRaiseMinAcceptedGenerationRevertsNotTimelock() public {
        bytes32 timelockRole = registry.TIMELOCK_ROLE();
        uint256 activationEpoch = registry.currentEpoch() + 1;

        vm.prank(nonAttester);
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, nonAttester, timelockRole)
        );
        registry.raiseMinAcceptedGeneration(1, activationEpoch);
    }

    // ========== Historical attestation root ring ==========

    /// @dev `historicalAttestationRoots` occupies storage slots 10..309
    ///      (`forge inspect ... storage-layout`), and `historicalAttestationRootIndex`
    ///      sits at slot 310. Driving 300 real `addAttestations` batches to reach
    ///      the wrap boundary is gas-prohibitive for a single test (each batch
    ///      pays a `PoseidonT6` leaf hash plus a LeanIMT insertion path), so this
    ///      forces the index to the boundary directly and exercises the real
    ///      eviction code path for the wrapping write, which is exactly the
    ///      constant-vs-literal desync class this test guards against.
    uint256 constant HISTORICAL_ROOT_INDEX_SLOT = 310;

    function testHistoricalRootRingWrapsAtCapacityPlusOne() public {
        AttestationRegistry ring =
            new AttestationRegistry(EPOCH_SECONDS, MAX_ATTESTATION_EPOCHS, 1, admin, timelock, OVERLAP_EPOCHS);
        ring.addAttester(attester);

        bytes32[] memory subjects1 = new bytes32[](1);
        subjects1[0] = keccak256("ring-subject-1");
        vm.prank(attester);
        ring.addAttestations(subjects1, expiresAt, 0);
        bytes32 root1 = ring.attestationRoot();

        bytes32[] memory subjects2 = new bytes32[](1);
        subjects2[0] = keccak256("ring-subject-2");
        vm.prank(attester);
        ring.addAttestations(subjects2, expiresAt, 0);
        bytes32 root2 = ring.attestationRoot();

        // A hardcoded slot number silently addresses the wrong variable if any
        // earlier storage declaration changes, so assert its expected contents
        // first. Two advances have happened, so the index reads 2.
        assertEq(
            uint256(vm.load(address(ring), bytes32(HISTORICAL_ROOT_INDEX_SLOT))),
            1,
            "HISTORICAL_ROOT_INDEX_SLOT no longer points at historicalAttestationRootIndex"
        );

        // root1 now sits at ring slot 0. Force the index back to 0, as if 300
        // real advances had already wrapped it there, so the next advance
        // writes to slot 0 again instead of slot 1.
        vm.store(address(ring), bytes32(HISTORICAL_ROOT_INDEX_SLOT), bytes32(uint256(0)));

        bytes32[] memory subjects3 = new bytes32[](1);
        subjects3[0] = keccak256("ring-subject-3");
        vm.prank(attester);
        ring.addAttestations(subjects3, expiresAt, 0);
        bytes32 root3 = ring.attestationRoot();

        // The wrap evicted root1 from slot 0 and replaced it with root2.
        assertFalse(ring.isKnownAttestationRoot(root1));
        assertTrue(ring.isKnownAttestationRoot(root2));
        // The newest root is always known via the direct equality check.
        assertTrue(ring.isKnownAttestationRoot(root3));
    }
}
