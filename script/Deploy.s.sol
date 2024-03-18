// SPDX-License-Identifier: CC0-1.0
// slither-disable-start reentrancy-benign

pragma solidity 0.8.23;

import {Script} from "forge-std/Script.sol";
import {ERC5564Announcer} from "src/ERC5564Announcer.sol";
import {ERC6538Registry} from "src/ERC6538Registry.sol";

contract Deploy is Script {
  ERC5564Announcer announcer;
  ERC6538Registry registry;
  address deployer = 0x4e59b44847b379578588920cA78FbF26c0B4956C;
  bytes32 ERC5564Salt = 0xd0103a290d760f027c9ca72675f5121d725397fb2f618f05b6c44958b25b4447;
  bytes32 ERC6538Salt = 0x0883790c70e6bce521db2517ae9873b2627580f5945fb2026117ab9d15ba9387;

  function run() public {
    bytes memory ERC5564CreationCode = abi.encodePacked(type(ERC5564Announcer).creationCode);
    bytes memory ERC6538CreationCode = abi.encodePacked(type(ERC6538Registry).creationCode);
    address ERC5564ComputedAddress =
      computeCreate2Address(ERC5564Salt, keccak256(ERC5564CreationCode), deployer);
    address ERC6538ComputedAddress =
      computeCreate2Address(ERC6538Salt, keccak256(ERC6538CreationCode), deployer);

    vm.broadcast();
    announcer = new ERC5564Announcer{salt: ERC5564Salt}();

    vm.broadcast();
    registry = new ERC6538Registry{salt: ERC6538Salt}();

    require(address(announcer) == ERC5564ComputedAddress, "announce address mismatch");
    require(address(registry) == ERC6538ComputedAddress, "registry address mismatch");
  }
}
