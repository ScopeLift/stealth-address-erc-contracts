// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Test} from "forge-std/Test.sol";
import {Deploy} from "script/Deploy.s.sol";

contract ERC6538RegistryTest is Test, Deploy {
  SigUtils internal sigUtils;

  event StealthMetaAddressSet(
    address indexed registrant, uint256 indexed schemeId, bytes stealthMetaAddress
  );

  function setUp() public {
    Deploy.run();
    sigUtils = new SigUtils(registry.DOMAIN_SEPARATOR());
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
  function testFuzz_AlwaysSucceeds(
    address caller,
    uint256 schemeId,
    bytes memory stealthMetaAddress
  ) external {
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
    SigUtils.RegistrantInfo memory registrantInfo =
      SigUtils.RegistrantInfo(alice, schemeId, stealthMetaAddress, 0 /* nonce */ );
    bytes32 hash = sigUtils.getTypedDataHash(registrantInfo);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, hash);
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.expectEmit(true, true, true, true);
    emit StealthMetaAddressSet(alice, schemeId, stealthMetaAddress);
    registry.registerKeysOnBehalf(alice, schemeId, signature, stealthMetaAddress, v, r, s);
  }

  function testFuzz_ERC1271SignatureIsValid(
    string memory name,
    uint256 schemeId,
    bytes memory stealthMetaAddress
  ) external {
    (address alice, uint256 alicePk) = makeAddrAndKey(name);

    vm.prank(alice);
    ERC1271MockContract erc1271MockContract = new ERC1271MockContract();
    address registrant = address(erc1271MockContract);

    SigUtils.RegistrantInfo memory registrantInfo =
      SigUtils.RegistrantInfo(registrant, schemeId, stealthMetaAddress, 0 /* nonce */ );
    bytes32 hash = sigUtils.getTypedDataHash(registrantInfo);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, hash);
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.expectEmit(true, true, true, true);
    emit StealthMetaAddressSet(registrant, schemeId, stealthMetaAddress);
    registry.registerKeysOnBehalf(registrant, schemeId, signature, stealthMetaAddress, v, r, s);
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
      SigUtils.RegistrantInfo memory registrantInfo =
        SigUtils.RegistrantInfo(alice, schemeId, stealthMetaAddress, nonce);
      bytes32 hash = sigUtils.getTypedDataHash(registrantInfo);
      (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, hash);
      bytes memory signature = abi.encodePacked(r, s, v);

      vm.expectEmit(true, true, true, true);
      emit StealthMetaAddressSet(alice, schemeId, stealthMetaAddress);
      registry.registerKeysOnBehalf(alice, schemeId, signature, stealthMetaAddress, v, r, s);
    }
  }

  function testFuzz_RevertIf_SignatureIsNotValid(
    string memory name,
    address bob,
    uint256 schemeId,
    bytes memory stealthMetaAddress
  ) external {
    (address alice, uint256 alicePk) = makeAddrAndKey(name);
    SigUtils.RegistrantInfo memory registrantInfo =
      SigUtils.RegistrantInfo(alice, schemeId, stealthMetaAddress, 0 /* nonce */ );
    bytes32 hash = sigUtils.getTypedDataHash(registrantInfo);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, hash);
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.expectRevert();
    registry.registerKeysOnBehalf(bob, schemeId, signature, stealthMetaAddress, v, r, s);
  }

  function testFuzz_RevertIf_WrongNonce(
    string memory name,
    uint256 schemeId,
    bytes memory stealthMetaAddress,
    uint256 nonce
  ) external {
    vm.assume(nonce != 0);
    (address alice, uint256 alicePk) = makeAddrAndKey(name);
    SigUtils.RegistrantInfo memory registrantInfo =
      SigUtils.RegistrantInfo(alice, schemeId, stealthMetaAddress, nonce);
    bytes32 hash = sigUtils.getTypedDataHash(registrantInfo);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, hash);
    bytes memory signature = abi.encodePacked(r, s, v);
    vm.expectRevert();
    registry.registerKeysOnBehalf(alice, schemeId, signature, stealthMetaAddress, v, r, s);
  }

  function test_RevertIf_NoSignatureIsProvided() external {
    vm.expectRevert();
    registry.registerKeysOnBehalf(address(0), 0, "", "", 0, 0, 0);
  }
}

contract ERC1271MockContract {
  address public owner;

  enum RecoverError {
    NoError,
    InvalidSignature,
    InvalidSignatureLength,
    InvalidSignatureS
  }

  error ECDSAInvalidSignature();
  error ECDSAInvalidSignatureLength(uint256 length);
  error ECDSAInvalidSignatureS(bytes32 s);

  constructor() {
    owner = msg.sender;
  }

  function isValidSignature(bytes32 hash, bytes memory signature)
    public
    view
    returns (bytes4 magicValue)
  {
    return recover(hash, signature) == owner ? this.isValidSignature.selector : bytes4(0);
  }

  function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
    (address recovered, RecoverError error, bytes32 errorArg) = tryRecover(hash, signature);
    _throwError(error, errorArg);
    return recovered;
  }

  function tryRecover(bytes32 hash, bytes memory signature)
    internal
    pure
    returns (address, RecoverError, bytes32)
  {
    if (signature.length == 65) {
      bytes32 r;
      bytes32 s;
      uint8 v;
      // ecrecover takes the signature parameters, and the only way to get them currently is to use
      // assembly.
      assembly ("memory-safe") {
        r := mload(add(signature, 0x20))
        s := mload(add(signature, 0x40))
        v := byte(0, mload(add(signature, 0x60)))
      }
      return tryRecover(hash, v, r, s);
    } else {
      return (address(0), RecoverError.InvalidSignatureLength, bytes32(signature.length));
    }
  }

  function tryRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s)
    internal
    pure
    returns (address, RecoverError, bytes32)
  {
    if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
      return (address(0), RecoverError.InvalidSignatureS, s);
    }

    // If the signature is valid (and not malleable), return the signer address
    address signer = ecrecover(hash, v, r, s);
    if (signer == address(0)) return (address(0), RecoverError.InvalidSignature, bytes32(0));

    return (signer, RecoverError.NoError, bytes32(0));
  }

  function _throwError(RecoverError error, bytes32 errorArg) private pure {
    if (error == RecoverError.NoError) {
      return; // no error: do nothing
    } else if (error == RecoverError.InvalidSignature) {
      revert ECDSAInvalidSignature();
    } else if (error == RecoverError.InvalidSignatureLength) {
      revert ECDSAInvalidSignatureLength(uint256(errorArg));
    } else if (error == RecoverError.InvalidSignatureS) {
      revert ECDSAInvalidSignatureS(errorArg);
    }
  }
}

contract SigUtils {
  bytes32 internal DOMAIN_SEPARATOR;

  constructor(bytes32 _DOMAIN_SEPARATOR) {
    DOMAIN_SEPARATOR = _DOMAIN_SEPARATOR;
  }

  bytes32 public constant TYPEHASH =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address registryContract)");

  struct RegistrantInfo {
    address registrant;
    uint256 schemeId;
    bytes stealthMetaAddress;
    uint256 nonce;
  }

  // computes the hash
  function getStructHash(RegistrantInfo memory _info) internal pure returns (bytes32) {
    return keccak256(
      abi.encode(TYPEHASH, _info.registrant, _info.schemeId, _info.stealthMetaAddress, _info.nonce)
    );
  }

  // computes the hash of the fully encoded EIP-712 message for the domain, which can be used to
  // recover the signer
  function getTypedDataHash(RegistrantInfo memory _info) public view returns (bytes32) {
    return keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, getStructHash(_info)));
  }
}
/// @notice Interface of the ERC1271 standard signature validation method for contracts as defined
/// in https://eips.ethereum.org/EIPS/eip-1271[ERC-1271].

interface IERC1271 {
  /// @dev Should return whether the signature provided is valid for the provided data
  /// @param hash      Hash of the data to be signed
  /// @param signature Signature byte array associated with _data
  function isValidSignature(bytes32 hash, bytes memory signature)
    external
    view
    returns (bytes4 magicValue);
}
