// SPDX-License-Identifier: CC0-1.0
pragma solidity 0.8.23;

import {Deploy} from "script/Deploy.s.sol";
import {Test} from "forge-std/Test.sol";
import {ERC5564Announcer} from "src/ERC5564Announcer.sol";
import {ERC6538Registry} from "src/ERC6538Registry.sol";

contract DeployTest is Test, Deploy {
  bytes announcerContractCode;
  ERC5564Announcer announcerTestDeployment;

  function setUp() public {
    announcerTestDeployment = new ERC5564Announcer();
    announcerContractCode = address(announcerTestDeployment).code;
  }

  function test_Deploy() external {
    bytes memory erc5564CreationCode = abi.encodePacked(type(ERC5564Announcer).creationCode);
    bytes memory erc6538CreationCode = abi.encodePacked(type(ERC6538Registry).creationCode);

    address erc5564ComputedAddress =
      computeCreate2Address(ERC5564Salt, keccak256(erc5564CreationCode), deployer);
    address erc6538ComputedAddress =
      computeCreate2Address(ERC6538Salt, keccak256(erc6538CreationCode), deployer);

    require(erc5564ComputedAddress.code.length == 0);
    require(erc6538ComputedAddress.code.length == 0);

    // Run deploy script
    Deploy.run();

    assertTrue(erc5564ComputedAddress.code.length > 0);
    assertTrue(erc6538ComputedAddress.code.length > 0);
    assertEq(erc5564ComputedAddress.code, announcerContractCode);
  }
}
