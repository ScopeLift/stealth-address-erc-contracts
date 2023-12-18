// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import {Deploy} from "script/Deploy.s.sol";

contract ERC6538RegistryTest is Test, Deploy {
  SigUtils internal sigUtils;

  event StealthMetaAddressSet(
    address indexed registrant, uint256 indexed schemeId, bytes stealthMetaAddress
  );

  function setUp() public {
    Deploy.run();
    sigUtils = new SigUtils(registry._domainSeparatorV4());
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
    SigUtils.RegistrantInfo memory registrantInfo =
      SigUtils.RegistrantInfo(alice, schemeId, stealthMetaAddress, 0 /* nonce */ );
    bytes32 hash = sigUtils.getTypedDataHash(registrantInfo);
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, hash);
    bytes memory signature = abi.encodePacked(r, s, v);

    vm.expectEmit(true, true, true, true);
    emit StealthMetaAddressSet(alice, schemeId, stealthMetaAddress);
    registry.registerKeysOnBehalf(alice, schemeId, signature, stealthMetaAddress);
  }

  // function testFuzz_ERC1271SignatureIsValid(
  //   string memory name,
  //   uint256 schemeId,
  //   bytes memory stealthMetaAddress
  // ) external {
  //   (address alice, uint256 alicePk) = makeAddrAndKey(name);
  //   SigUtils.RegistrantInfo memory registrantInfo =
  //     SigUtils.RegistrantInfo(alice, schemeId, stealthMetaAddress, 0);
  //   bytes32 hash = sigUtils.getTypedDataHash(registrantInfo);
  //   (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, hash);
  //   bytes memory signature = abi.encodePacked(r, s, v);

  //   vm.prank(alice);
  //   ERC1271CompatibleContract erc1271CompatibleContract = new ERC1271CompatibleContract();
  //   vm.expectEmit(true, true, true, true);
  //   emit StealthMetaAddressSet(alice, schemeId, stealthMetaAddress);
  //   vm.prank(address(erc1271CompatibleContract));
  //   registry.registerKeysOnBehalf(alice, schemeId, signature, stealthMetaAddress);
  // }

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

// contract ERC1271CompatibleContract is Test {
//   address owner;

//   /**
//    * @notice Verifies that the signer is the owner of the signing contract.
//    */

//   constructor() {
//     owner = msg.sender;
//   }

//   function isValidSignature(bytes32 _hash, bytes calldata _signature)
//     external
//     view
//     returns (bytes4)
//   {
//     // Validate signatures
//     if (recoverSigner(_hash, _signature) == owner) return 0x1626ba7e;
//     else return 0xffffffff;
//   }

//   /**
//    * @notice Recover the signer of hash, assuming it's an EOA account
//    * @dev Only for EthSign signatures
//    * @param _hash       Hash of message that was signed
//    * @param _signature  Signature encoded as (bytes32 r, bytes32 s, uint8 v)
//    */
//   function recoverSigner(bytes32 _hash, bytes memory _signature)
//     internal
//     pure
//     returns (address signer)
//   {
//     require(_signature.length == 65, "SignatureValidator#recoverSigner: invalid signature
// length");

//     // Variables are not scoped in Solidity.
//     uint8 v = uint8(_signature[64]);
//     (, bytes32 r) = readBytes32(_signature, 0);
//     (, bytes32 s) = readBytes32(_signature, 32);

//     // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and
// make
//     // the signature
//     // unique. Appendix F in the Ethereum Yellow paper
//     // (https://ethereum.github.io/yellowpaper/paper.pdf), defines
//     // the valid range for s in (281): 0 < s < secp256k1n ÷ 2 + 1, and for v in (282): v ∈ {27,
//     // 28}. Most
//     // signatures from current libraries generate a unique signature with an s-value in the lower
//     // half order.
//     //
//     // If your library generates malleable signatures, such as s-values in the upper range,
//     // calculate a new s-value
//     // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v
// from
//     // 27 to 28 or
//     // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27
// to
//     // v to accept
//     // these malleable signatures as well.
//     //
//     // Source OpenZeppelin
//     //
// https://github.com/OpenZeppelin/openzeppelin-contracts/blob/master/contracts/cryptography/ECDSA.sol

//     if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
//       revert("SignatureValidator#recoverSigner: invalid signature 's' value");
//     }

//     if (v != 27 && v != 28) revert("SignatureValidator#recoverSigner: invalid signature 'v'
// value");

//     // Recover ECDSA signer
//     signer = ecrecover(_hash, v, r, s);

//     // Prevent signer from being 0x0
//     require(signer != address(0x0), "SignatureValidator#recoverSigner: INVALID_SIGNER");

//     return signer;
//   }

//   function readBytes32(bytes memory _data, uint256 _offset)
//     internal
//     pure
//     returns (uint256 newOffset, bytes32 r)
//   {
//     newOffset = _offset + 32;
//     r = bytesToBytes32(_data, _offset);
//   }

//   function bytesToBytes32(bytes memory _bytes, uint256 _start) internal pure returns (bytes32 r)
// {
//     uint256 offset = _start + 0x20;
//     require(_bytes.length >= offset, "Y");
//     assembly {
//       r := mload(add(_bytes, offset))
//     }
//   }
// }

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

  // computes the hash of a permit
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
