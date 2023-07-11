// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import {Deploy} from "script/Deploy.s.sol";
import {ERC5564Announcer} from "src/ERC5564Announcer.sol";

contract ERC5564AnnouncerTest is Test, Deploy {
  function setUp() public {
    Deploy.run();
  }
}
