// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

import {IERC6538Registry} from "./interfaces/IERC6538Registry.sol";
import {SignatureChecker} from "@openzeppelin/contracts/utils/cryptography/SignatureChecker.sol";

/// @dev `ERC6538Registry` contract to map accounts to their stealth meta-address. See
/// [ERC-6538](https://eips.ethereum.org/EIPS/eip-6538) to learn more.
contract ERC6538Registry is IERC6538Registry {
  /// @notice Maps a registrant's identifier to the scheme ID to the stealth meta-address.
  /// @dev `registrant` may be a standard 160-bit address or any other identifier.
  /// @dev `schemeId` is an integer identifier for the stealth address scheme.
  mapping(address registrant => mapping(uint256 schemeId => bytes)) public stealthMetaAddressOf;

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
    bytes32 digest = keccak256(abi.encode(registrant, schemeId, stealthMetaAddress));
    require(
      SignatureChecker.isValidSignatureNow(registrant, digest, signature), "Invalid signature"
    );
    stealthMetaAddressOf[registrant][schemeId] = stealthMetaAddress;
    emit StealthMetaAddressSet(registrant, schemeId, stealthMetaAddress);
  }
}
