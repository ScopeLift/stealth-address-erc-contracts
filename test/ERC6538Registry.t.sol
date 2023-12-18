// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import {Deploy} from "script/Deploy.s.sol";

contract ERC6538RegistryTest is Test, Deploy {
  event StealthMetaAddressSet(
    address indexed registrant, uint256 indexed schemeId, bytes stealthMetaAddress
  );

  function setUp() public {
    Deploy.run();
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
    emit StealthMetaAddressSet(caller, schemeId, stealthMetaAddress);
    registry.registerKeys(schemeId, stealthMetaAddress);
  }

  function testFuzz_CorrectlyMapsRegistrantToSchemeIdToStealthMetaAddressInStorage(
    address caller,
    uint256 schemeId,
    bytes memory stealthMetaAddress
  ) external {
    assertEq(registry.stealthMetaAddressOf((caller), schemeId), "");
    vm.prank(caller);
    registry.registerKeys(schemeId, stealthMetaAddress);
    assertEq(registry.stealthMetaAddressOf((caller), schemeId), stealthMetaAddress);
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

contract RegisterKeysOnBehalf_Address is ERC6538RegistryTest {
  function testFuzz_SignatureIsValid(
    string memory name,
    uint256 schemeId,
    bytes memory stealthMetaAddress
  ) external {
    (address alice, uint256 alicePk) = makeAddrAndKey(name);
    bytes32 hash = keccak256(abi.encode(alice, schemeId, stealthMetaAddress, 0));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, hash);
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.expectEmit(true, true, true, true);
    emit StealthMetaAddressSet(alice, schemeId, stealthMetaAddress);
    registry.registerKeysOnBehalf(alice, schemeId, signature, stealthMetaAddress);
  }

  function testFuzz_UpdateStealthMetaAddress(
    string memory name,
    uint256 schemeId,
    bytes memory stealthMetaAddress,
    uint256 numOfUpdates
  ) external {
    numOfUpdates = bound(numOfUpdates, 1, 50);
    (address alice, uint256 alicePk) = makeAddrAndKey(name);

    for (uint256 nonce = 0; nonce < numOfUpdates; nonce++) {
      bytes32 hash = keccak256(abi.encode(alice, schemeId, stealthMetaAddress, nonce));
      (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, hash);
      bytes memory signature = abi.encodePacked(r, s, v);

      vm.expectEmit(true, true, true, true);
      emit StealthMetaAddressSet(alice, schemeId, stealthMetaAddress);
      registry.registerKeysOnBehalf(alice, schemeId, signature, stealthMetaAddress);
    }
  }

  function testFuzz_RevertIf_SignatureIsNotValid(
    string memory name,
    address bob,
    uint256 schemeId,
    bytes memory stealthMetaAddress
  ) external {
    (address alice, uint256 alicePk) = makeAddrAndKey(name);
    bytes32 hash = keccak256(abi.encode(alice, schemeId, stealthMetaAddress, 0));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, hash);
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.expectRevert("Invalid signature");
    registry.registerKeysOnBehalf(bob, schemeId, signature, stealthMetaAddress);
  }

  function testFuzz_RevertIf_WrongNonce(
    string memory name,
    uint256 schemeId,
    bytes memory stealthMetaAddress,
    uint256 nonce
  ) external {
    vm.assume(nonce != 0);
    (address alice, uint256 alicePk) = makeAddrAndKey(name);
    bytes32 hash = keccak256(abi.encode(alice, schemeId, stealthMetaAddress, nonce));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, hash);
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.expectRevert("Invalid signature");
    registry.registerKeysOnBehalf(alice, schemeId, signature, stealthMetaAddress);
  }

  function test_RevertIf_NoSignatureIsProvided() external {
    vm.expectRevert("Invalid signature");
    registry.registerKeysOnBehalf(address(0), 0, "", "");
  }
}
