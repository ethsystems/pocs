// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";

/// @notice One leaf per attester, rewritten in place on lowering, so the
///         structure is non-monotone and cannot be a LeanIMT. Fixed depth
///         because it is recomputed in full on every write.
struct AttesterRevocationTreeData {
    address[] attesters;
    mapping(address => uint64) revokedAtEpoch;
    mapping(address => bool) isAttester;
    bytes32 cachedRoot;
    mapping(address => uint64) revocationFloor;
}

/// @title AttesterRevocationTree
/// @notice Fixed-depth binary Merkle tree of `(attester, revokedAtEpoch)` pairs.
///         Leaf `Poseidon1(attester, revokedAtEpoch)`, empty slot `Poseidon1(0, 0)`.
///         Rebuilt from the stored attester array on every insert, remove, and
///         lowering, which is 32 leaf hashes plus 31 internal-node hashes.
///         The result is cached, because the pool reads the root once per gated
///         operation and governance writes are rare.
library AttesterRevocationTree {
    uint256 internal constant DEPTH = 5;
    uint256 internal constant CAPACITY = 2 ** DEPTH;

    error AttesterAlreadyExists();
    error AttesterDoesNotExist();
    error RevocationTreeFull();

    /// @notice Seeds `cachedRoot` with the all-empty-slots root. MUST be called once
    ///         at construction, or the first read returns zero rather than the root
    ///         of an empty tree.
    function init(AttesterRevocationTreeData storage self) internal returns (bytes32) {
        self.cachedRoot = _computeRoot(self);
        return self.cachedRoot;
    }

    function insert(AttesterRevocationTreeData storage self, address attester) internal returns (bytes32) {
        if (self.isAttester[attester]) revert AttesterAlreadyExists();
        if (self.attesters.length >= CAPACITY) revert RevocationTreeFull();

        self.isAttester[attester] = true;
        // Zero is a safe "unset" sentinel: AttestationRegistry.lowerRevocation
        // requires newRevokedAtEpoch >= currentEpoch(), and the pool constructor
        // requires epochSeconds <= block.timestamp, so currentEpoch() >= 1 for
        // any deployed instance. A floor can therefore never legitimately be 0.
        uint64 floor = self.revocationFloor[attester];
        self.revokedAtEpoch[attester] = floor == 0 ? type(uint64).max : floor;
        self.attesters.push(attester);

        return _refresh(self);
    }

    /// @dev Swap-and-pop frees the slot back to empty. Any subject holding a
    ///      witness for `attester`'s leaf can no longer produce an inclusion
    ///      proof against the resulting root, so removal reaches attestations
    ///      already issued.
    function remove(AttesterRevocationTreeData storage self, address attester) internal returns (bytes32) {
        if (!self.isAttester[attester]) revert AttesterDoesNotExist();

        self.isAttester[attester] = false;
        delete self.revokedAtEpoch[attester];

        uint256 len = self.attesters.length;
        for (uint256 i = 0; i < len; i++) {
            if (self.attesters[i] == attester) {
                self.attesters[i] = self.attesters[len - 1];
                self.attesters.pop();
                break;
            }
        }

        return _refresh(self);
    }

    function lower(AttesterRevocationTreeData storage self, address attester, uint64 newRevokedAtEpoch)
        internal
        returns (bytes32)
    {
        if (!self.isAttester[attester]) revert AttesterDoesNotExist();
        self.revokedAtEpoch[attester] = newRevokedAtEpoch;
        self.revocationFloor[attester] = newRevokedAtEpoch;
        return _refresh(self);
    }

    function contains(AttesterRevocationTreeData storage self, address attester) internal view returns (bool) {
        return self.isAttester[attester];
    }

    function revokedAtEpochOf(AttesterRevocationTreeData storage self, address attester)
        internal
        view
        returns (uint64)
    {
        return self.revokedAtEpoch[attester];
    }

    /// @dev A plain storage read. The pool reads this once per gated operation, so
    ///      recomputing here would put a full 63-hash rebuild on every deposit,
    ///      transfer, and gated withdraw.
    function root(AttesterRevocationTreeData storage self) internal view returns (bytes32) {
        return self.cachedRoot;
    }

    function _refresh(AttesterRevocationTreeData storage self) private returns (bytes32) {
        self.cachedRoot = _computeRoot(self);
        return self.cachedRoot;
    }

    function _computeRoot(AttesterRevocationTreeData storage self) private view returns (bytes32) {
        uint256[CAPACITY] memory nodes;
        uint256 n = self.attesters.length;
        uint256 emptyLeaf = PoseidonT3.hash([uint256(0), uint256(0)]);

        for (uint256 i = 0; i < CAPACITY; i++) {
            if (i < n) {
                address a = self.attesters[i];
                nodes[i] = PoseidonT3.hash([uint256(uint160(a)), uint256(self.revokedAtEpoch[a])]);
            } else {
                nodes[i] = emptyLeaf;
            }
        }

        uint256 levelSize = CAPACITY;
        while (levelSize > 1) {
            uint256 half = levelSize / 2;
            for (uint256 i = 0; i < half; i++) {
                nodes[i] = PoseidonT3.hash([nodes[2 * i], nodes[2 * i + 1]]);
            }
            levelSize = half;
        }

        return bytes32(nodes[0]);
    }
}
