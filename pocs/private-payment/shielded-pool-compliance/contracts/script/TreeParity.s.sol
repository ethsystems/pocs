// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/src/Script.sol";
import {console} from "forge-std/src/console.sol";
import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";
import {LeanIMT, LeanIMTData} from "@zk-kit/packages/lean-imt/contracts/LeanIMT.sol";
import {AttesterRevocationTreeHarness} from "../test/AttesterRevocationTree.t.sol";

/// @notice Storage host for the zk-kit LeanIMT, using the same public library
///         `ShieldedPool` uses so the parity run exercises the deployed code path.
contract LeanIMTHost {
    using LeanIMT for LeanIMTData;

    LeanIMTData internal _tree;

    function insert(uint256 leaf) external returns (uint256) {
        return _tree.insert(leaf);
    }

    function root() external view returns (uint256) {
        return _tree.root();
    }
}

/// @notice Inserts `PARITY_LEAVES` one at a time and logs the root after each
///         insert, so a single run covers every leaf-count prefix including the
///         odd counts where LeanIMT promotes an unpaired node.
contract CommitmentTreeParity is Script {
    function run() external {
        uint256[] memory leaves = vm.envUint("PARITY_LEAVES", ",");
        LeanIMTHost host = new LeanIMTHost();

        for (uint256 i = 0; i < leaves.length; i++) {
            host.insert(leaves[i]);
            console.log(string.concat("COMMITMENT_ROOT_", vm.toString(i + 1), "=", vm.toString(bytes32(host.root()))));
        }
    }
}

/// @notice Replays an attester operation list against the on-chain revocation
///         tree, then folds a Rust-produced inclusion path with the on-chain
///         Poseidon so a path that disagrees fails even when the roots agree.
contract RevocationTreeParity is Script {
    uint256 private constant OP_ADD = 0;
    uint256 private constant OP_REMOVE = 1;
    uint256 private constant OP_LOWER = 2;

    function run() external {
        // Op word: kind << 224 | revokedAtEpoch << 160 | uint160(attester).
        uint256[] memory ops = vm.envUint("REVOCATION_OPS", ",");
        AttesterRevocationTreeHarness harness = new AttesterRevocationTreeHarness();

        for (uint256 i = 0; i < ops.length; i++) {
            address attester = address(uint160(ops[i]));
            uint256 kind = ops[i] >> 224;
            if (kind == OP_ADD) {
                harness.insert(attester);
            } else if (kind == OP_REMOVE) {
                harness.remove(attester);
            } else if (kind == OP_LOWER) {
                harness.lower(attester, uint64(ops[i] >> 160));
            } else {
                revert("unknown revocation op kind");
            }
        }

        console.log(string.concat("REVOCATION_ROOT=", vm.toString(harness.root())));

        address subject = vm.envAddress("REVOCATION_SUBJECT");
        console.log(string.concat("REVOCATION_SUBJECT_EPOCH=", vm.toString(uint256(harness.revokedAtEpochOf(subject)))));

        uint256 node = vm.envUint("REVOCATION_PATH_LEAF");
        uint256[] memory siblings = vm.envUint("REVOCATION_PATH_SIBLINGS", ",");
        // Side 0 means the proved node is the left child, matching `Side::Left`.
        uint256[] memory sides = vm.envUint("REVOCATION_PATH_SIDES", ",");
        require(siblings.length == sides.length, "path sibling/side length mismatch");

        for (uint256 i = 0; i < siblings.length; i++) {
            node = sides[i] == 0 ? PoseidonT3.hash([node, siblings[i]]) : PoseidonT3.hash([siblings[i], node]);
        }

        console.log(string.concat("REVOCATION_PATH_ROOT=", vm.toString(bytes32(node))));
    }
}
