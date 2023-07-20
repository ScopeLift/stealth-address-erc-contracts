// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

import {IERC6538Registry} from "./interfaces/IERC6538Registry.sol";

/// @dev `ERC6538Registry` contract to map accounts to their stealth meta-address. See
/// [ERC-6538](https://eips.ethereum.org/EIPS/eip-6538) to learn more.
contract ERC6538Registry is IERC6538Registry {
  /// @notice Maps a registrant's identifier to the scheme ID to the stealth meta-address.
  /// @dev `registrant` may be a standard 160-bit address or any other identifier.
  /// @dev `schemeId` is an integer identifier for the stealth address scheme.
  mapping(bytes registrant => mapping(uint256 schemeId => bytes)) public stealthMetaAddressOf;

  /// @inheritdoc IERC6538Registry
  function registerKeys(uint256 schemeId, bytes memory stealthMetaAddress) external {
    bytes memory registrant = _toBytes(msg.sender);
    stealthMetaAddressOf[registrant][schemeId] = stealthMetaAddress;
    emit StealthMetaAddressSet(registrant, schemeId, stealthMetaAddress);
  }

  /// @inheritdoc IERC6538Registry
  function registerKeysOnBehalf(
    address registrant,
    uint256 schemeId,
    bytes memory signature,
    bytes memory stealthMetaAddress
  ) external pure {
    registerKeysOnBehalf(_toBytes(registrant), schemeId, signature, stealthMetaAddress);
  }

  /// @inheritdoc IERC6538Registry
  function registerKeysOnBehalf(
    bytes memory, // registrant
    uint256, // schemeId
    bytes memory, // signature
    bytes memory // stealthMetaAddress
  ) public pure {
    revert("not implemented");
  }

  /// @dev Converts an `address` to `bytes`.
  function _toBytes(address who) internal pure returns (bytes memory) {
    return bytes.concat(bytes32(uint256(uint160(who))));
  }
}
