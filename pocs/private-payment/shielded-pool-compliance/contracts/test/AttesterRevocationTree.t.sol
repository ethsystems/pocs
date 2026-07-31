// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";
import {AttesterRevocationTree, AttesterRevocationTreeData} from "../src/AttesterRevocationTree.sol";

/// @notice Thin harness exposing the internal library over its own storage,
///         so the library's mechanics are testable independent of
///         AttestationRegistry.
contract AttesterRevocationTreeHarness {
    using AttesterRevocationTree for AttesterRevocationTreeData;

    AttesterRevocationTreeData internal _tree;

    /// @dev Mirrors `AttestationRegistry`'s constructor. Without it `root()` reads
    ///      zero rather than the all-empty-slots root.
    constructor() {
        _tree.init();
    }

    function insert(address attester) external returns (bytes32) {
        return _tree.insert(attester);
    }

    function remove(address attester) external returns (bytes32) {
        return _tree.remove(attester);
    }

    function lower(address attester, uint64 newRevokedAtEpoch) external returns (bytes32) {
        return _tree.lower(attester, newRevokedAtEpoch);
    }

    function root() external view returns (bytes32) {
        return _tree.root();
    }

    function contains(address attester) external view returns (bool) {
        return _tree.contains(attester);
    }

    function revokedAtEpochOf(address attester) external view returns (uint64) {
        return _tree.revokedAtEpochOf(attester);
    }
}

contract AttesterRevocationTreeTest is Test {
    AttesterRevocationTreeHarness internal harness;

    function setUp() public {
        harness = new AttesterRevocationTreeHarness();
    }

    function _emptyLeaf() internal pure returns (uint256) {
        return PoseidonT3.hash([uint256(0), uint256(0)]);
    }

    /// @dev Hand-rolled depth-5 rebuild over whatever pairs are populated, for
    ///      cross-checking the library's root against an independent
    ///      computation.
    function _expectedRoot(address[] memory attesters, uint64[] memory revokedAt) internal pure returns (bytes32) {
        uint256 capacity = 32;
        uint256[] memory nodes = new uint256[](capacity);
        uint256 empty = PoseidonT3.hash([uint256(0), uint256(0)]);
        for (uint256 i = 0; i < capacity; i++) {
            if (i < attesters.length) {
                nodes[i] = PoseidonT3.hash([uint256(uint160(attesters[i])), uint256(revokedAt[i])]);
            } else {
                nodes[i] = empty;
            }
        }
        uint256 levelSize = capacity;
        while (levelSize > 1) {
            uint256 half = levelSize / 2;
            for (uint256 i = 0; i < half; i++) {
                nodes[i] = PoseidonT3.hash([nodes[2 * i], nodes[2 * i + 1]]);
            }
            levelSize = half;
        }
        return bytes32(nodes[0]);
    }

    // ========== Empty tree ==========

    function testEmptyTreeRootIsAllEmptyLeaves() public view {
        address[] memory attesters = new address[](0);
        uint64[] memory revokedAt = new uint64[](0);
        assertEq(harness.root(), _expectedRoot(attesters, revokedAt));
    }

    // ========== Insert ==========

    function testInsertMatchesHandRolledRoot() public {
        address a1 = address(0x1);
        address a2 = address(0x2);

        harness.insert(a1);
        harness.insert(a2);

        address[] memory attesters = new address[](2);
        attesters[0] = a1;
        attesters[1] = a2;
        uint64[] memory revokedAt = new uint64[](2);
        revokedAt[0] = type(uint64).max;
        revokedAt[1] = type(uint64).max;

        assertEq(harness.root(), _expectedRoot(attesters, revokedAt));
    }

    function testInsertRevertsOnDuplicate() public {
        address attester = address(0x1);
        harness.insert(attester);

        vm.expectRevert(AttesterRevocationTree.AttesterAlreadyExists.selector);
        harness.insert(attester);
    }

    /// @dev Filling the tree with 32 real inserts costs a full rebuild each
    ///      time (~1.3M gas apiece, see `testRebuildGas`), which is
    ///      gas-prohibitive for a single test. `_tree.attesters` is the first
    ///      field of the harness's only storage slot, so its length lives at
    ///      slot 0; forcing it to `CAPACITY` exercises the same guard the
    ///      32nd real insert would trip, without paying for 31 rebuilds first.
    function testInsertRevertsWhenFull() public {
        vm.store(address(harness), bytes32(uint256(0)), bytes32(uint256(32)));

        vm.expectRevert(AttesterRevocationTree.RevocationTreeFull.selector);
        harness.insert(address(uint160(33)));
    }

    // ========== Remove ==========

    function testRemoveRevertsOnUnknownAttester() public {
        vm.expectRevert(AttesterRevocationTree.AttesterDoesNotExist.selector);
        harness.remove(address(0x1));
    }

    function testRemoveSoleAttesterRestoresEmptyRoot() public {
        address attester = address(0x1);
        bytes32 emptyRoot = harness.root();

        harness.insert(attester);
        assertTrue(harness.root() != emptyRoot);

        harness.remove(attester);
        assertEq(harness.root(), emptyRoot);
        assertFalse(harness.contains(attester));
    }

    function testRemoveFreesSlotForReuse() public {
        address a1 = address(0x1);
        harness.insert(a1);
        harness.remove(a1);

        // An attester that was never lowered has no floor, so re-adding it
        // starts a fresh type(uint64).max pair.
        harness.insert(a1);
        assertTrue(harness.contains(a1));
        assertEq(harness.revokedAtEpochOf(a1), type(uint64).max);
    }

    function testRemoveThenReAddPreservesRevocationFloor() public {
        address a1 = address(0x1);
        harness.insert(a1);
        harness.lower(a1, 7);
        harness.remove(a1);
        harness.insert(a1);

        assertEq(harness.revokedAtEpochOf(a1), 7);

        address[] memory attesters = new address[](1);
        attesters[0] = a1;
        uint64[] memory revokedAt = new uint64[](1);
        revokedAt[0] = 7;
        assertEq(harness.root(), _expectedRoot(attesters, revokedAt));
    }

    // ========== Lower ==========

    function testLowerRevertsOnUnknownAttester() public {
        vm.expectRevert(AttesterRevocationTree.AttesterDoesNotExist.selector);
        harness.lower(address(0x1), 5);
    }

    function testLowerChangesRoot() public {
        address attester = address(0x1);
        harness.insert(attester);
        bytes32 rootBefore = harness.root();

        harness.lower(attester, 7);

        assertTrue(harness.root() != rootBefore);
        assertEq(harness.revokedAtEpochOf(attester), 7);
    }

    function testRootStableAcrossUnrelatedReads() public {
        address attester = address(0x1);
        harness.insert(attester);

        bytes32 root1 = harness.root();
        bytes32 root2 = harness.root();
        assertTrue(harness.contains(attester));
        bytes32 root3 = harness.root();

        assertEq(root1, root2);
        assertEq(root2, root3);
    }

    // ========== Gas ==========

    function testRebuildGas() public {
        for (uint256 i = 0; i < 10; i++) {
            harness.insert(address(uint160(i + 1)));
        }

        uint256 gasBefore = gasleft();
        harness.lower(address(uint160(1)), 3);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("AttesterRevocationTree rebuild gas (10 attesters, one lowering)", gasUsed);
        assertTrue(gasUsed > 0);
    }
}
