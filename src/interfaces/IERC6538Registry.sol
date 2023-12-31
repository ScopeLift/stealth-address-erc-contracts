// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

/// @dev Interface for calling the `ERC6538Registry` contract to map accounts to their stealth
/// meta-address. See [ERC-6538](https://eips.ethereum.org/EIPS/eip-6538) to learn more.
interface IERC6538Registry {
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
    bytes indexed registrant, uint256 indexed schemeId, bytes stealthMetaAddress
  );

  /// @notice Sets the caller's stealth meta-address for the given scheme ID.
  /// @param schemeId Identifier corresponding to the applied stealth address scheme, e.g. 0 for
  /// secp256k1, as specified in ERC-5564.
  /// @param stealthMetaAddress The stealth meta-address to register.
  function registerKeys(uint256 schemeId, bytes memory stealthMetaAddress) external;

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
  ) external;

  /// @notice Sets the `registrant`s stealth meta-address for the given scheme ID.
  /// @param registrant Recipient identifier, such as an address.
  /// @param schemeId Identifier corresponding to the applied stealth address scheme, e.g. 0 for
  /// secp256k1, as specified in ERC-5564.
  /// @param signature A signature from the `registrant` authorizing the registration.
  /// @param stealthMetaAddress The stealth meta-address to register.
  /// @dev Supports both EOA signatures and EIP-1271 signatures.
  /// @dev Reverts if the signature is invalid.
  function registerKeysOnBehalf(
    bytes memory registrant,
    uint256 schemeId,
    bytes memory signature,
    bytes memory stealthMetaAddress
  ) external;
}
