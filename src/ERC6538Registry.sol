// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

/// @dev `ERC6538Registry` contract to map accounts to their stealth meta-address. See
/// [ERC-6538](https://eips.ethereum.org/EIPS/eip-6538) to learn more.
contract ERC6538Registry {
  /// @notice Next nonce expected from `user` to use when signing for `registerKeysOnBehalf`.
  /// @dev `registrant` may be a standard 160-bit address or any other identifier.
  /// @dev `schemeId` is an integer identifier for the stealth address scheme.
  mapping(address registrant => mapping(uint256 schemeId => bytes stealthMetaAddress)) public
    stealthMetaAddressOf;

  /// @notice A nonce used to ensure a signature can only be used once.
  /// @dev `user` is the registrant address.
  /// @dev `nonce` will be incremented after each valid `registerKeysOnBehalf` call.
  mapping(address user => uint256 nonce) public nonceOf;

  /// @dev EIP-712 Type hash used in `registerKeysOnBehalf`.
  bytes32 public constant TYPE_HASH =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address registryContract)");

  /// @dev The domain separator used in this contract.
  bytes32 public immutable domainSeparator;

  enum RecoverError {
    NoError,
    InvalidSignature,
    InvalidSignatureLength,
    InvalidSignatureS
  }

  /// @dev Emitted when a registrant updates their stealth meta-address.
  /// @param registrant The account that registered the stealth meta-address.
  /// @param schemeId Identifier corresponding to the applied stealth address scheme, e.g. 0 for
  /// secp256k1, as specified in ERC-5564.
  /// @param stealthMetaAddress The stealth meta-address.
  /// [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) bases the format for stealth
  /// meta-addresses on [ERC-3770](https://eips.ethereum.org/EIPS/eip-3770) and specifies them as:
  ///   st:<shortName>:0x<spendingPubKey>:<viewingPubKey>
  /// The chain (`shortName`) is implicit based on the chain the `ERC6538Registry` is deployed on,
  /// therefore this `stealthMetaAddress` is just the `spendingPubKey` and `viewingPubKey`
  /// concatenated.
  event StealthMetaAddressSet(
    address indexed registrant, uint256 indexed schemeId, bytes stealthMetaAddress
  );

  constructor() {
    domainSeparator =
      keccak256(abi.encode(TYPE_HASH, "ERC6538Registry", "1.0", block.chainid, address(this)));
  }

  /// @notice Sets the caller's stealth meta-address for the given scheme ID.
  /// @param schemeId Identifier corresponding to the applied stealth address scheme, e.g. 0 for
  /// secp256k1, as specified in ERC-5564.
  /// @param stealthMetaAddress The stealth meta-address to register.
  function registerKeys(uint256 schemeId, bytes memory stealthMetaAddress) external {
    stealthMetaAddressOf[msg.sender][schemeId] = stealthMetaAddress;
    emit StealthMetaAddressSet(msg.sender, schemeId, stealthMetaAddress);
  }

  /// @notice Sets the `registrant`'s stealth meta-address for the given scheme ID.
  /// @param registrant Address of the registrant.
  /// @param schemeId Identifier corresponding to the applied stealth address scheme, e.g. 0 for
  /// secp256k1, as specified in ERC-5564.
  /// @param signature A signature from the `registrant` authorizing the registration.
  /// @param stealthMetaAddress The stealth meta-address to register.
  /// @dev Supports both EOA signatures and EIP-1271 signatures.
  /// @dev Reverts if the signature is invalid.
  function registerKeysOnBehalf(
    address registrant,
    uint256 schemeId,
    bytes memory signature,
    bytes memory stealthMetaAddress
  ) external {
    bytes32 digest = _hashTypedDataV4(
      keccak256(
        abi.encode(TYPE_HASH, registrant, schemeId, stealthMetaAddress, nonceOf[registrant]++)
      )
    );
    require(isValidSignatureNow(registrant, digest, signature), "Invalid signature");
    stealthMetaAddressOf[registrant][schemeId] = stealthMetaAddress;
    emit StealthMetaAddressSet(registrant, schemeId, stealthMetaAddress);
  }

  /// @notice Increments the nonce of the sender to invalidate existing signatures.
  function incrementNonce() external {
    nonceOf[msg.sender]++;
  }

  /// @notice Returns the hash of the fully encoded EIP712 message for this domain.
  /// @dev The following code is modified from OpenZeppelin's `EIP712.sol` file. Permalink:
  /// https://github.com/OpenZeppelin/openzeppelin-contracts/blob/e70a0118ef10773457f670671baefad2c5ea610d/contracts/utils/cryptography/EIP712.sol
  /// @param structHash The hash of the struct containing the message data, as defined in
  /// https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct
  function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32) {
    return toTypedDataHash(domainSeparator, structHash);
  }

  /// @dev Returns the keccak256 digest of an EIP-712 typed data (ERC-191 version `0x01`).
  /// @dev The digest is calculated from a `domainSeparator` and a `structHash`, by prefixing them
  /// with `\x19\x01` and hashing the result. It corresponds to the hash signed by the
  /// https://eips.ethereum.org/EIPS/eip-712[`eth_signTypedData`] JSON-RPC method as part of
  /// EIP-712.
  /// @dev The following code is from OpenZeppelin's `MessageHashUtils.sol` file. Permalink:
  /// https://github.com/OpenZeppelin/openzeppelin-contracts/blob/e70a0118ef10773457f670671baefad2c5ea610d/contracts/utils/cryptography/MessageHashUtils.sol
  /// @param contractDomainSeparator The domain separator.
  /// @param structHash The hash of the struct containing the message data, as defined in
  /// https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct
  function toTypedDataHash(bytes32 contractDomainSeparator, bytes32 structHash)
    internal
    pure
    returns (bytes32 digest)
  {
    /// @solidity memory-safe-assembly
    assembly {
      let ptr := mload(0x40)
      mstore(ptr, hex"1901")
      mstore(add(ptr, 0x02), contractDomainSeparator)
      mstore(add(ptr, 0x22), structHash)
      digest := keccak256(ptr, 0x42)
    }
  }

  /// @notice Checks if a signature is valid for a given signer and data hash. If the signer is a
  /// smart contract, the signature is validated against that smart contract using ERC1271,
  /// otherwise it's validated using `tryRecover`.
  /// @dev The following code is from OpenZeppelin's `SignatureChecker.sol` file. Permalink:
  /// https://github.com/OpenZeppelin/openzeppelin-contracts/blob/e70a0118ef10773457f670671baefad2c5ea610d/contracts/utils/cryptography/SignatureChecker.sol
  /// @param signer The address that should have signed the message data.
  /// @param hash The digest of message data.
  /// @param signature The signature provided by the registrant.
  function isValidSignatureNow(address signer, bytes32 hash, bytes memory signature)
    internal
    view
    returns (bool)
  {
    (address recovered, RecoverError error,) = tryRecover(hash, signature);
    return (error == RecoverError.NoError && recovered == signer)
      || isValidERC1271SignatureNow(signer, hash, signature);
  }

  /// @notice Checks if a signature is valid for a given signer and data hash. The signature is
  /// validated against the signer smart contract using ERC1271.
  /// @dev The following code is modified from OpenZeppelin's `SignatureChecker.sol` file. Permalink:
  /// https://github.com/OpenZeppelin/openzeppelin-contracts/blob/e70a0118ef10773457f670671baefad2c5ea610d/contracts/utils/cryptography/SignatureChecker.sol
  /// @param signer The address that should have signed the message data.
  /// @param hash The digest of message data.
  /// @param signature The signature provided by the registrant.
  function isValidERC1271SignatureNow(address signer, bytes32 hash, bytes memory signature)
    internal
    view
    returns (bool)
  {
    (bool success, bytes memory result) = signer.staticcall(
      abi.encodeWithSelector(bytes4(keccak256("isValidSignature(bytes32,bytes)")), hash, signature)
    );
    return (
      success && result.length >= 32
        && abi.decode(result, (bytes32))
          == bytes32(bytes4(keccak256("isValidSignature(bytes32,bytes)")))
    );
  }

  /// @dev The following code is from OpenZeppelin's `ECDSA.sol` file. Permalink:
  /// https://github.com/OpenZeppelin/openzeppelin-contracts/blob/e70a0118ef10773457f670671baefad2c5ea610d/contracts/utils/cryptography/ECDSA.sol
  /// @param hash The digest of message data.
  /// @param signature The signature provided by the registrant.
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

  /// @notice Recover the signer's address using `v`, `r` and `s` signature fields.
  /// @dev The following code is from OpenZeppelin's `ECDSA.sol` file. Permalink:
  /// https://github.com/OpenZeppelin/openzeppelin-contracts/blob/e70a0118ef10773457f670671baefad2c5ea610d/contracts/utils/cryptography/ECDSA.sol
  function tryRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s)
    internal
    pure
    returns (address, RecoverError, bytes32)
  {
    // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make
    // the signature unique. Appendix F in the Ethereum Yellow paper
    // (https://ethereum.github.io/yellowpaper/paper.pdf), defines the valid range for s in (301):
    // 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}. Most signatures from
    // current libraries generate a unique signature with an s-value in the lower half order.

    // If your library generates malleable signatures, such as s-values in the upper range,
    // calculate a new s-value with
    // 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27
    // to 28 or vice versa. If your library also generates signatures with 0/1 for v instead 27/28,
    // add 27 to v to accept these malleable signatures as well.
    if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
      return (address(0), RecoverError.InvalidSignatureS, s);
    }

    // If the signature is valid (and not malleable), return the signer address
    address signer = ecrecover(hash, v, r, s);
    if (signer == address(0)) return (address(0), RecoverError.InvalidSignature, bytes32(0));

    return (signer, RecoverError.NoError, bytes32(0));
  }
}
