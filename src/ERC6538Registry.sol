// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

import {IERC6538Registry} from "./interfaces/IERC6538Registry.sol";

/// @dev `ERC6538Registry` contract to map accounts to their stealth meta-address. See
/// [ERC-6538](https://eips.ethereum.org/EIPS/eip-6538) to learn more.
contract ERC6538Registry is IERC6538Registry {
  /// @notice Maps a registrant's identifier to the scheme ID to the stealth meta-address.
  /// @dev `registrant` may be a standard 160-bit address or any other identifier.
  /// @dev `schemeId` is an integer identifier for the stealth address scheme.
  mapping(address registrant => mapping(uint256 schemeId => bytes stealthMetaAddress)) public
    stealthMetaAddressOf;
  mapping(address user => uint256 nonce) public nonceOf;

  bytes32 private constant TYPE_HASH =
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address registryContract)");

  // Cache the domain separator as an immutable value, but also store the chain id that it
  // corresponds to, in order to
  // invalidate the cached domain separator if the chain id changes.
  bytes32 private immutable _cachedDomainSeparator;
  uint256 private immutable _cachedChainId;
  address private immutable _cachedThis;

  bytes32 private immutable _hashedName;
  bytes32 private immutable _hashedVersion;

  string private _name;
  string private _version;

  enum RecoverError {
    NoError,
    InvalidSignature,
    InvalidSignatureLength,
    InvalidSignatureS
  }

  constructor() {
    _name = "ERC6538Registry";
    _version = "1";
    _hashedName = keccak256(bytes("ERC6538Registry"));
    _hashedVersion = keccak256(bytes("1"));
    _cachedChainId = block.chainid;
    _cachedDomainSeparator = _buildDomainSeparator();
    _cachedThis = address(this);
  }

  /// @inheritdoc IERC6538Registry
  function registerKeys(uint256 schemeId, bytes memory stealthMetaAddress) external {
    stealthMetaAddressOf[msg.sender][schemeId] = stealthMetaAddress;
    emit StealthMetaAddressSet(msg.sender, schemeId, stealthMetaAddress);
  }

  /// @inheritdoc IERC6538Registry
  function registerKeysOnBehalf(
    address registrant,
    uint256 schemeId,
    bytes memory signature,
    bytes memory stealthMetaAddress
  ) external {
    // Check for nonce
    bytes32 digest = _hashTypedDataV4(
      keccak256(
        abi.encode(TYPE_HASH, registrant, schemeId, stealthMetaAddress, nonceOf[registrant]++)
      )
    );
    require(isValidSignatureNow(registrant, digest, signature), "Invalid signature");
    stealthMetaAddressOf[registrant][schemeId] = stealthMetaAddress;
    emit StealthMetaAddressSet(registrant, schemeId, stealthMetaAddress);
  }

  /**
   * @dev Returns the domain separator for the current chain.
   */
  function _domainSeparatorV4() public view returns (bytes32) {
    if (address(this) == _cachedThis && block.chainid == _cachedChainId) {
      return _cachedDomainSeparator;
    } else {
      return _buildDomainSeparator();
    }
  }

  function _buildDomainSeparator() private view returns (bytes32) {
    return
      keccak256(abi.encode(TYPE_HASH, _hashedName, _hashedVersion, block.chainid, address(this)));
  }

  /**
   * @dev Given an already https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct[hashed
   * struct], this
   * function returns the hash of the fully encoded EIP712 message for this domain.
   *
   * This hash can be used together with {ECDSA-recover} to obtain the signer of a message. For
   * example:
   *
   * ```solidity
   * bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
   *     keccak256("Mail(address to,string contents)"),
   *     mailTo,
   *     keccak256(bytes(mailContents))
   * )));
   * address signer = ECDSA.recover(digest, signature);
   * ```
   */
  function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32) {
    return toTypedDataHash(_domainSeparatorV4(), structHash);
  }

  /**
   * @dev Returns the keccak256 digest of an EIP-712 typed data (ERC-191 version `0x01`).
   *
   * The digest is calculated from a `domainSeparator` and a `structHash`, by prefixing them with
   * `\x19\x01` and hashing the result. It corresponds to the hash signed by the
   * https://eips.ethereum.org/EIPS/eip-712[`eth_signTypedData`] JSON-RPC method as part of EIP-712.
   *
   * See {ECDSA-recover}.
   */
  function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash)
    internal
    pure
    returns (bytes32 digest)
  {
    /// @solidity memory-safe-assembly
    assembly {
      let ptr := mload(0x40)
      mstore(ptr, hex"1901")
      mstore(add(ptr, 0x02), domainSeparator)
      mstore(add(ptr, 0x22), structHash)
      digest := keccak256(ptr, 0x42)
    }
  }

  /**
   * @dev Checks if a signature is valid for a given signer and data hash. If the signer is a smart
   * contract, the
   * signature is validated against that smart contract using ERC1271, otherwise it's validated
   * using `ECDSA.recover`.
   */
  function isValidSignatureNow(address signer, bytes32 hash, bytes memory signature)
    internal
    view
    returns (bool)
  {
    (address recovered, RecoverError error,) = tryRecover(hash, signature);
    return (error == RecoverError.NoError && recovered == signer)
      || isValidERC1271SignatureNow(signer, hash, signature);
  }

  /**
   * @dev Checks if a signature is valid for a given signer and data hash. The signature is
   * validated
   * against the signer smart contract using ERC1271.
   */
  function isValidERC1271SignatureNow(address signer, bytes32 hash, bytes memory signature)
    internal
    view
    returns (bool)
  {
    (bool success, bytes memory result) =
      signer.staticcall(abi.encodeCall(IERC1271.isValidSignature, (hash, signature)));
    return (
      success && result.length >= 32
        && abi.decode(result, (bytes32)) == bytes32(IERC1271.isValidSignature.selector)
    );
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
      // ecrecover takes the signature parameters, and the only way to get them
      // currently is to use assembly.
      /// @solidity memory-safe-assembly
      assembly {
        r := mload(add(signature, 0x20))
        s := mload(add(signature, 0x40))
        v := byte(0, mload(add(signature, 0x60)))
      }
      return tryRecover(hash, v, r, s);
    } else {
      return (address(0), RecoverError.InvalidSignatureLength, bytes32(signature.length));
    }
  }

  /**
   * @dev Overload of {ECDSA-tryRecover} that receives the `v`,
   * `r` and `s` signature fields separately.
   */
  function tryRecover(bytes32 hash, uint8 v, bytes32 r, bytes32 s)
    internal
    pure
    returns (address, RecoverError, bytes32)
  {
    // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make
    // the signature
    // unique. Appendix F in the Ethereum Yellow paper
    // (https://ethereum.github.io/yellowpaper/paper.pdf), defines
    // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27,
    // 28}. Most
    // signatures from current libraries generate a unique signature with an s-value in the lower
    // half order.
    //
    // If your library generates malleable signatures, such as s-values in the upper range,
    // calculate a new s-value
    // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from
    // 27 to 28 or
    // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to
    // v to accept
    // these malleable signatures as well.
    if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
      return (address(0), RecoverError.InvalidSignatureS, s);
    }

    // If the signature is valid (and not malleable), return the signer address
    address signer = ecrecover(hash, v, r, s);
    if (signer == address(0)) return (address(0), RecoverError.InvalidSignature, bytes32(0));

    return (signer, RecoverError.NoError, bytes32(0));
  }
}

/**
 * @dev Interface of the ERC1271 standard signature validation method for
 * contracts as defined in https://eips.ethereum.org/EIPS/eip-1271[ERC-1271].
 */
interface IERC1271 {
  /**
   * @dev Should return whether the signature provided is valid for the provided data
   * @param hash      Hash of the data to be signed
   * @param signature Signature byte array associated with _data
   */
  function isValidSignature(bytes32 hash, bytes memory signature)
    external
    view
    returns (bytes4 magicValue);
}
