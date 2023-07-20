// SPDX-License-Identifier: UNLICENSED
// slither-disable-start reentrancy-benign

pragma solidity 0.8.20;

import {Script} from "forge-std/Script.sol";
import {ERC5564Announcer} from "src/ERC5564Announcer.sol";

contract Deploy is Script {
  ERC5564Announcer announcer;

  function run() public {
    vm.broadcast();
    announcer = new ERC5564Announcer();
  }
}
