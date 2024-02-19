// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Test} from "forge-std/Test.sol";
import {Deploy} from "script/Deploy.s.sol";
import {ERC6538Registry, IERC1271} from "src/ERC6538Registry.sol";

contract ERC6538RegistryTest is Test, Deploy {
  error ERC6538Registry__InvalidSignature();

  event StealthMetaAddressSet(
    address indexed registrant, uint256 indexed schemeId, bytes stealthMetaAddress
  );
  event NonceIncremented(address indexed registrant, uint256 newNonce);

  function setUp() public {
    Deploy.run();
  }

  // Test helper to compute EIP712 domain separator for a given chain id and deployment address
  function _computeDomainSeparator(uint256 _chainId, address _registryAddress)
    public
    pure
    returns (bytes32)
  {
    return keccak256(
      abi.encode(
        keccak256(
          "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        ),
        keccak256("ERC6538Registry"),
        keccak256("1.0"),
        _chainId,
        _registryAddress
      )
    );
  }

  function _generateRegistrationSignature(
    uint256 _registrantPrivateKey,
    uint256 _schemeId,
    bytes memory _stealthMetaAddress,
    uint256 _nonce
  ) public view returns (bytes memory _signature) {
    bytes32 _dataHash = keccak256(
      abi.encode(registry.ERC6538REGISTRY_ENTRY_TYPE_HASH(), _schemeId, _stealthMetaAddress, _nonce)
    );
    bytes32 _hash = keccak256(abi.encodePacked("\x19\x01", registry.DOMAIN_SEPARATOR(), _dataHash));
    (uint8 v, bytes32 r, bytes32 s) = vm.sign(_registrantPrivateKey, _hash);
    _signature = abi.encodePacked(r, s, v);
  }

  function _notVmOrConsole(address _address) public pure {
    // This function is used to avoid calling the VM or the console, which would return error
    // messages. It is used in tests where we want assert a function reverts without a message.
    vm.assume(_address != address(vm));
    vm.assume(_address != address(address(0x000000000000000000636F6e736F6c652e6c6f67)));
  }

  function manipulateSignature(bytes memory signature) public pure returns (bytes memory) {
    (uint8 v, bytes32 r, bytes32 s) = splitSignature(signature);

    uint8 manipulatedV = v % 2 == 0 ? v - 1 : v + 1;
    uint256 manipulatedS = modNegS(uint256(s));
    bytes memory manipulatedSignature = abi.encodePacked(r, bytes32(manipulatedS), manipulatedV);

    return manipulatedSignature;
  }

  function splitSignature(bytes memory sig) public pure returns (uint8 v, bytes32 r, bytes32 s) {
    require(sig.length == 65, "Invalid signature length");
    assembly {
      r := mload(add(sig, 32))
      s := mload(add(sig, 64))
      v := byte(0, mload(add(sig, 96)))
    }
    if (v < 27) v += 27;
    require(v == 27 || v == 28, "Invalid signature v value");
  }

  function modNegS(uint256 s) public pure returns (uint256) {
    uint256 n = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
    return n - s;
  }
}

// Test harness to expose internal contract methods for test purpose only
contract ERC6538RegistryHarness is ERC6538Registry {
  function exposed_INITIAL_CHAIN_ID() public view returns (uint256) {
    return INITIAL_CHAIN_ID;
  }

  function exposed_INITIAL_DOMAIN_SEPARATOR() public view returns (bytes32) {
    return INITIAL_DOMAIN_SEPARATOR;
  }
}

contract Constructor is ERC6538RegistryTest {
  function test_SetsTheInitialChainId() external {
    ERC6538RegistryHarness _registry = new ERC6538RegistryHarness();
    assertEq(_registry.exposed_INITIAL_CHAIN_ID(), block.chainid);
  }

  function test_SetsTheInitialDomainSeparator() external {
    ERC6538RegistryHarness _registry = new ERC6538RegistryHarness();
    assertEq(
      _registry.exposed_INITIAL_DOMAIN_SEPARATOR(),
      _computeDomainSeparator(block.chainid, address(_registry))
    );
  }
}

contract RegisterKeys is ERC6538RegistryTest {
  function testFuzz_EmitsASetEvent(
    address caller,
    uint256 schemeId,
    bytes memory stealthMetaAddress
  ) external {
    vm.prank(caller);
    vm.expectEmit();
    emit StealthMetaAddressSet(caller, schemeId, stealthMetaAddress);
    registry.registerKeys(schemeId, stealthMetaAddress);
  }

  function testFuzz_SetsTheStealthMetaAddressForANewRegistrant(
    address caller,
    uint256 schemeId,
    bytes memory stealthMetaAddress
  ) external {
    vm.prank(caller);
    registry.registerKeys(schemeId, stealthMetaAddress);

    assertEq(registry.stealthMetaAddressOf((caller), schemeId), stealthMetaAddress);
  }

  function testFuzz_UpdatesTheStealthMetaAddressForAnExistingRegistrant(
    address caller,
    uint256 schemeId,
    bytes memory stealthMetaAddress1,
    bytes memory stealthMetaAddress2
  ) external {
    vm.prank(caller);
    registry.registerKeys(schemeId, stealthMetaAddress1);
    assertEq(registry.stealthMetaAddressOf((caller), schemeId), stealthMetaAddress1);

    vm.prank(caller);
    registry.registerKeys(schemeId, stealthMetaAddress2);
    assertEq(registry.stealthMetaAddressOf((caller), schemeId), stealthMetaAddress2);
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

contract RegisterKeysOnBehalf is ERC6538RegistryTest {
  function testFuzz_SetsTheStealthMetaAddressForANewRegistrantWhenProvidedAValidErc712Signature(
    string memory registrantSeed,
    uint256 schemeId,
    bytes memory stealthMetaAddress
  ) external {
    (address registrant, uint256 registrantPrivateKey) = makeAddrAndKey(registrantSeed);
    bytes memory signature =
      _generateRegistrationSignature(registrantPrivateKey, schemeId, stealthMetaAddress, 0);

    registry.registerKeysOnBehalf(registrant, schemeId, signature, stealthMetaAddress);
    assertEq(registry.stealthMetaAddressOf(registrant, schemeId), stealthMetaAddress);
  }

  function testFuzz_EmitsAStealthMetaAddressSetEventForANewRegistrantWhenProvidedAValidErc712Signature(
    string memory registrantSeed,
    uint256 schemeId,
    bytes memory stealthMetaAddress
  ) external {
    (address registrant, uint256 registrantPrivateKey) = makeAddrAndKey(registrantSeed);
    bytes memory signature =
      _generateRegistrationSignature(registrantPrivateKey, schemeId, stealthMetaAddress, 0);

    vm.expectEmit();
    emit StealthMetaAddressSet(registrant, schemeId, stealthMetaAddress);
    registry.registerKeysOnBehalf(registrant, schemeId, signature, stealthMetaAddress);
  }

  function testFuzz_SetsTheStealthMetaAddressForANewRegistrantWhenProvidedAValidErc1271Signature(
    uint256 schemeId,
    bytes memory stealthMetaAddress,
    bytes memory signature
  ) external {
    MockERC1271Signer mockRegistrant = new MockERC1271Signer();
    mockRegistrant.setResponse__isValidSignature(true);

    registry.registerKeysOnBehalf(address(mockRegistrant), schemeId, signature, stealthMetaAddress);
    assertEq(registry.stealthMetaAddressOf(address(mockRegistrant), schemeId), stealthMetaAddress);
  }

  function testFuzz_EmitsAStealthMetaAddressSetEventForANewRegistrantWhenProvidedAValidErc1271Signature(
    uint256 schemeId,
    bytes memory stealthMetaAddress,
    bytes memory signature
  ) external {
    MockERC1271Signer mockRegistrant = new MockERC1271Signer();
    mockRegistrant.setResponse__isValidSignature(true);

    vm.expectEmit();
    emit StealthMetaAddressSet(address(mockRegistrant), schemeId, stealthMetaAddress);
    registry.registerKeysOnBehalf(address(mockRegistrant), schemeId, signature, stealthMetaAddress);
  }

  function testFuzz_UpdatesTheStealthMetaAddressForAnExistingRegistrantWhenProvidedAValidErc712Signature(
    string memory registrantSeed,
    uint256 schemeId,
    bytes memory stealthMetaAddress,
    uint256 numOfUpdates
  ) external {
    numOfUpdates = bound(numOfUpdates, 2, 50);
    (address registrant, uint256 registrantPrivateKey) = makeAddrAndKey(registrantSeed);

    for (uint256 nonce = 0; nonce < numOfUpdates; nonce++) {
      bytes memory signature =
        _generateRegistrationSignature(registrantPrivateKey, schemeId, stealthMetaAddress, nonce);

      registry.registerKeysOnBehalf(registrant, schemeId, signature, stealthMetaAddress);
      assertEq(registry.stealthMetaAddressOf(registrant, schemeId), stealthMetaAddress);
    }
  }

  function testFuzz_UpdatesTheStealthMetaAddressForAnExistingRegistrantWhenProvidedAValidErc1271Signature(
    uint256 schemeId,
    bytes memory stealthMetaAddress,
    bytes memory signature,
    uint256 numOfUpdates
  ) external {
    numOfUpdates = bound(numOfUpdates, 2, 50);

    MockERC1271Signer mockRegistrant = new MockERC1271Signer();
    mockRegistrant.setResponse__isValidSignature(true);

    for (uint256 nonce = 0; nonce < numOfUpdates; nonce++) {
      registry.registerKeysOnBehalf(
        address(mockRegistrant), schemeId, signature, stealthMetaAddress
      );
      assertEq(registry.stealthMetaAddressOf(address(mockRegistrant), schemeId), stealthMetaAddress);
    }
  }

  function testFuzz_RevertIf_TheDataIsErc712SignedByAnAddressOtherThanTheRegistrant(
    string memory seed,
    address registrant,
    uint256 schemeId,
    bytes memory stealthMetaAddress
  ) external {
    (address notRegistrant, uint256 notRegistrantPrivateKey) = makeAddrAndKey(seed);
    vm.assume(notRegistrant != registrant);
    _notVmOrConsole(registrant);
    bytes memory signature =
      _generateRegistrationSignature(notRegistrantPrivateKey, schemeId, stealthMetaAddress, 0);

    vm.expectRevert(bytes(""));
    registry.registerKeysOnBehalf(registrant, schemeId, signature, stealthMetaAddress);
  }

  function testFuzz_RevertIf_TheRegistrantErc712SignsOverTheWrongSchemeId(
    string memory registrantSeed,
    uint256 schemeId,
    uint256 wrongSchemeId,
    bytes memory stealthMetaAddress
  ) external {
    vm.assume(schemeId != wrongSchemeId);
    (address registrant, uint256 registrantPrivateKey) = makeAddrAndKey(registrantSeed);

    bytes memory signature =
      _generateRegistrationSignature(registrantPrivateKey, wrongSchemeId, stealthMetaAddress, 0);

    vm.expectRevert(bytes(""));
    registry.registerKeysOnBehalf(registrant, schemeId, signature, stealthMetaAddress);
  }

  function testFuzz_RevertIf_TheRegistrantErc712SignsOverTheWrongStealthMetaAddress(
    string memory registrantSeed,
    uint256 schemeId,
    bytes memory stealthMetaAddress,
    bytes memory wrongStealthAMetaAddress
  ) external {
    vm.assume(keccak256(stealthMetaAddress) != keccak256(wrongStealthAMetaAddress));
    (address registrant, uint256 registrantPrivateKey) = makeAddrAndKey(registrantSeed);

    bytes memory signature =
      _generateRegistrationSignature(registrantPrivateKey, schemeId, wrongStealthAMetaAddress, 0);

    vm.expectRevert(bytes(""));
    registry.registerKeysOnBehalf(registrant, schemeId, signature, stealthMetaAddress);
  }

  function testFuzz_RevertIf_ANewRegistrantErc712SignsOverANonZeroNonce(
    string memory registrantSeed,
    uint256 schemeId,
    bytes memory stealthMetaAddress,
    uint256 nonce
  ) external {
    vm.assume(nonce != 0);
    (address registrant, uint256 registrantPrivateKey) = makeAddrAndKey(registrantSeed);
    bytes memory signature =
      _generateRegistrationSignature(registrantPrivateKey, schemeId, stealthMetaAddress, nonce);

    vm.expectRevert(bytes(""));
    registry.registerKeysOnBehalf(registrant, schemeId, signature, stealthMetaAddress);
  }

  function testFuzz_RevertIf_APreviouslyUsedErc712SignatureIsReplayed(
    string memory registrantSeed,
    uint256 schemeId,
    bytes memory stealthMetaAddress
  ) external {
    (address registrant, uint256 registrantPrivateKey) = makeAddrAndKey(registrantSeed);
    bytes memory signature =
      _generateRegistrationSignature(registrantPrivateKey, schemeId, stealthMetaAddress, 0);

    registry.registerKeysOnBehalf(registrant, schemeId, signature, stealthMetaAddress);

    vm.expectRevert(bytes(""));
    registry.registerKeysOnBehalf(registrant, schemeId, signature, stealthMetaAddress);
  }

  function testFuzz_RevertIf_AManipulatedErc712SignatureIsUsedToRegister(
    string memory registrantSeed,
    uint256 schemeId,
    bytes memory stealthMetaAddress
  ) external {
    (address registrant, uint256 registrantPrivateKey) = makeAddrAndKey(registrantSeed);
    bytes memory signature =
      _generateRegistrationSignature(registrantPrivateKey, schemeId, stealthMetaAddress, 0);
    bytes memory manipulatedSignature = manipulateSignature(signature);

    vm.expectRevert(bytes(""));
    registry.registerKeysOnBehalf(registrant, schemeId, manipulatedSignature, stealthMetaAddress);
  }

  function testFuzz_RevertIf_AManipulatedErc712SignatureIsUsedToRegisterADifferentStealthMetaAddress(
    string memory registrantSeed,
    uint256 schemeId,
    bytes memory stealthMetaAddress,
    bytes memory attackerStealthMetaAddress
  ) external {
    vm.assume(keccak256(stealthMetaAddress) != keccak256(attackerStealthMetaAddress));
    (address registrant, uint256 registrantPrivateKey) = makeAddrAndKey(registrantSeed);
    bytes memory signature =
      _generateRegistrationSignature(registrantPrivateKey, schemeId, stealthMetaAddress, 0);
    bytes memory manipulatedSignature = manipulateSignature(signature);

    vm.expectRevert(bytes(""));
    registry.registerKeysOnBehalf(
      registrant, schemeId, manipulatedSignature, attackerStealthMetaAddress
    );
  }

  function testFuzz_RevertIf_TheErc1271SignatureIsNotValid(
    uint256 schemeId,
    bytes memory stealthMetaAddress,
    bytes memory signature
  ) external {
    MockERC1271Signer mockRegistrant = new MockERC1271Signer();
    mockRegistrant.setResponse__isValidSignature(false);

    vm.expectRevert(ERC6538Registry__InvalidSignature.selector);
    registry.registerKeysOnBehalf(address(mockRegistrant), schemeId, signature, stealthMetaAddress);
  }

  function testFuzz_RevertIf_AnEmptySignatureIsSubmitted(
    address registrant,
    uint256 schemeId,
    bytes memory stealthMetaAddress
  ) external {
    _notVmOrConsole(registrant);
    vm.expectRevert(bytes(""));
    registry.registerKeysOnBehalf(registrant, schemeId, "", stealthMetaAddress);
  }
}

contract IncrementNonce is ERC6538RegistryTest {
  function testFuzz_IncrementsTheNonceOfTheCaller(address registrant, uint256 numOfCalls) external {
    numOfCalls = bound(numOfCalls, 2, 50);

    for (uint256 i = 1; i < numOfCalls; i++) {
      vm.prank(registrant);
      registry.incrementNonce();

      assertEq(registry.nonceOf(registrant), i);
    }
  }

  function testFuzz_EmitsANonceIncrementedEvent(address registrant) external {
    uint256 expectedNonce = registry.nonceOf(registrant) + 1;
    vm.expectEmit();
    emit NonceIncremented(registrant, expectedNonce);
    vm.prank(registrant);
    registry.incrementNonce();
  }
}

contract Domain_Separator is ERC6538RegistryTest {
  function test_ReturnsTheValueComputedAtDeploymentIfChainIdRemainsUnchanged() external {
    ERC6538RegistryHarness _registry = new ERC6538RegistryHarness();
    assertEq(_registry.DOMAIN_SEPARATOR(), _registry.exposed_INITIAL_DOMAIN_SEPARATOR());
  }

  function testFuzz_ReturnsARecomputedValueIfTheChainIdChanges(uint256 chainId1, uint256 chainId2)
    external
  {
    chainId1 = bound(chainId1, 1, 2 ** 64 - 1);
    chainId2 = bound(chainId2, 1, 2 ** 64 - 1);

    vm.chainId(chainId1);
    assertEq(registry.DOMAIN_SEPARATOR(), _computeDomainSeparator(chainId1, address(registry)));

    vm.chainId(chainId2);
    assertEq(registry.DOMAIN_SEPARATOR(), _computeDomainSeparator(chainId2, address(registry)));
  }
}

contract MockERC1271Signer is IERC1271 {
  bytes4 public constant MAGICVALUE = 0x1626ba7e;
  bytes4 public response__isValidSignature;

  function setResponse__isValidSignature(bool _nextResponse) external {
    if (_nextResponse) {
      // If the mock should signal the signature is valid, it should return the MAGICVALUE
      response__isValidSignature = MAGICVALUE;
    } else {
      // If the mock should signal it is not valid, we'll return an arbitrary four bytes derived
      // from the address where the mock happens to be deployed
      response__isValidSignature = bytes4(keccak256(abi.encode(address(this))));
    }
  }

  function isValidSignature(bytes32, /* hash */ bytes memory /* signature */ )
    external
    view
    returns (bytes4 magicValue)
  {
    magicValue = response__isValidSignature;
  }
}
