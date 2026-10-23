// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/src/Test.sol";
import {PoseidonT2} from "poseidon-solidity/PoseidonT2.sol";
import {PoseidonT3} from "poseidon-solidity/PoseidonT3.sol";
import {PoseidonT4} from "poseidon-solidity/PoseidonT4.sol";
import {PoseidonT5} from "poseidon-solidity/PoseidonT5.sol";
import {PoseidonT6} from "poseidon-solidity/PoseidonT6.sol";

contract PoseidonTest is Test {
    // ========== Arity 1 ==========

    function testPoseidonArity1() public pure {
        uint256 result = PoseidonT2.hash([uint256(1)]);
        assertEq(result, 18586133768512220936620570745912940619677854269274689475585506675881198879027);
    }

    // ========== Arity 2 ==========

    function testPoseidonArity2() public pure {
        uint256 result = PoseidonT3.hash([uint256(1), uint256(2)]);
        assertEq(result, 7853200120776062878684798364095072458815029376092732009249414926327459813530);
    }

    // ========== Arity 3 ==========

    function testPoseidonArity3() public pure {
        uint256 result = PoseidonT4.hash([uint256(1), uint256(2), uint256(3)]);
        assertEq(result, 6542985608222806190361240322586112750744169038454362455181422643027100751666);
    }

    // ========== Arity 4 ==========

    function testPoseidonArity4() public pure {
        uint256 result = PoseidonT5.hash([uint256(1), uint256(2), uint256(3), uint256(4)]);
        assertEq(result, 18821383157269793795438455681495246036402687001665670618754263018637548127333);
    }

    // ========== Arity 5 ==========

    function testPoseidonArity5() public pure {
        uint256 result = PoseidonT6.hash([uint256(1), uint256(2), uint256(3), uint256(4), uint256(5)]);
        assertEq(result, 6183221330272524995739186171720101788151706631170188140075976616310159254464);
    }
}
