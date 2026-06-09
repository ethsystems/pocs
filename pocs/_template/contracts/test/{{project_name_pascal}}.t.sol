// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.13;

import {Test} from "forge-std/src/Test.sol";
import { {{project_name_pascal}} } from "../src/{{project_name_pascal}}.sol";

contract {{project_name_pascal}}Test is Test {
    {{project_name_pascal}} public {{project-name | lower_camel_case}};

    function setUp() public {
        {{project-name | lower_camel_case}} = new {{project_name_pascal}}();
        {{project-name | lower_camel_case}}.setNumber(0);
    }

    function test_Increment() public {
        {{project-name | lower_camel_case}}.increment();
        assertEq({{project-name | lower_camel_case}}.number(), 1);
    }

    function testFuzz_SetNumber(uint256 x) public {
        {{project-name | lower_camel_case}}.setNumber(x);
        assertEq({{project-name | lower_camel_case}}.number(), x);
    }
}
