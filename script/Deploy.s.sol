// SPDX-License-Identifier: UNLICENSED
// slither-disable-start reentrancy-benign

pragma solidity 0.8.20;

import {Script} from "forge-std/Script.sol";
import {ERC5564Announcer} from "src/ERC5564Announcer.sol";
import {ERC6538Registry} from "src/ERC6538Registry.sol";

contract Deploy is Script {
  ERC5564Announcer announcer;
  ERC6538Registry registry;

  function run() public {
    // Nice to have: Check address matches the expected one
    vm.broadcast();
    announcer = new ERC5564Announcer{salt: ""}();

    vm.broadcast();
    registry = new ERC6538Registry{salt: ""}();
    // Check here
  }
}
