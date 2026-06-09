// SPDX-License-Identifier: MIT OR Apache-2.0
pragma solidity ^0.8.13;

import {Script} from "forge-std/src/Script.sol";
import { {{project_name_pascal}} } from "../src/{{project_name_pascal}}.sol";

contract {{project_name_pascal}}Script is Script {
    {{project_name_pascal}} public {{project-name | lower_camel_case}};

    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        {{project-name | lower_camel_case}} = new {{project_name_pascal}}();

        vm.stopBroadcast();
    }
}
