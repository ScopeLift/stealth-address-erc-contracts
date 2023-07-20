// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import {Deploy} from "script/Deploy.s.sol";

contract ERC5564AnnouncerTest is Test, Deploy {
  event Announcement(
    uint256 indexed schemeId,
    address indexed stealthAddress,
    address indexed caller,
    bytes ephemeralPubKey,
    bytes metadata
  );

  function setUp() public {
    Deploy.run();
  }
}

contract Announce is ERC5564AnnouncerTest {
  function testFuzz_EmitsAnnouncementEvent(
    uint256 schemeId,
    address stealthAddress,
    address caller,
    bytes memory ephemeralPubKey,
    bytes memory metadata
  ) external {
    vm.prank(caller);
    vm.expectEmit();
    emit Announcement(schemeId, stealthAddress, caller, ephemeralPubKey, metadata);
    announcer.announce(schemeId, stealthAddress, ephemeralPubKey, metadata);
  }

  // This test is a subset of `testFuzz_EmitsAnnouncementEvent`, and is mainly present to make
  // the `announce` method's specification more explicit. For this reason, we set the number of runs
  // to 1 for all profiles.
  /// forge-config: default.fuzz.runs = 1
  /// forge-config: ci.fuzz.runs = 1
  /// forge-config: lite.fuzz.runs = 1
  function testFuzz_NeverReverts(
    uint256 schemeId,
    address stealthAddress,
    address caller,
    bytes memory ephemeralPubKey,
    bytes memory metadata
  ) external {
    vm.prank(caller);
    announcer.announce(schemeId, stealthAddress, ephemeralPubKey, metadata);
  }
}
