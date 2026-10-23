// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Script} from "forge-std/src/Script.sol";
import {console} from "forge-std/src/console.sol";
import {LeanIMT, LeanIMTData} from "@zk-kit/packages/lean-imt/contracts/LeanIMT.sol";

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
