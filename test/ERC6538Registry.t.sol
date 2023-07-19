// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import {Deploy} from "script/Deploy.s.sol";

contract ERC6538RegistryTest is Test, Deploy {
  event StealthMetaAddressSet(
    bytes indexed registrant, uint256 indexed schemeId, bytes stealthMetaAddress
  );

  function setUp() public {
    Deploy.run();
  }

  function toBytes(address who) internal pure returns (bytes memory) {
    return bytes.concat(bytes32(uint256(uint160(who))));
  }
}

contract RegisterKeys is ERC6538RegistryTest {
  function testFuzz_EmitsStealthMetaAddressSetEvent(
    address caller,
    uint256 schemeId,
    bytes memory stealthMetaAddress
  ) external {
    vm.prank(caller);
    vm.expectEmit();
    emit StealthMetaAddressSet(toBytes(caller), schemeId, stealthMetaAddress);
    registry.registerKeys(schemeId, stealthMetaAddress);
  }

  function testFuzz_CorrectlyMapsRegistrantToSchemeIdToStealthMetaAddressInStorage(
    address caller,
    uint256 schemeId,
    bytes memory stealthMetaAddress
  ) external {
    assertEq(registry.stealthMetaAddressOf(toBytes(caller), schemeId), "");
    vm.prank(caller);
    registry.registerKeys(schemeId, stealthMetaAddress);
    assertEq(registry.stealthMetaAddressOf(toBytes(caller), schemeId), stealthMetaAddress);
  }

  // This test is a subset of `testFuzz_EmitsStealthMetaAddressSetEvent`, and is mainly present to
  // make the `announce` method's specification more explicit. For this reason, we set the number of
  // runs to 1 for all profiles.
  /// forge-config: default.fuzz.runs = 1
  /// forge-config: ci.fuzz.runs = 1
  /// forge-config: lite.fuzz.runs = 1
  function testFuzz_NeverReverts(address caller, uint256 schemeId, bytes memory stealthMetaAddress)
    external
  {
    vm.prank(caller);
    registry.registerKeys(schemeId, stealthMetaAddress);
  }
}
