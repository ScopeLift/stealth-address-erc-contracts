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
}
