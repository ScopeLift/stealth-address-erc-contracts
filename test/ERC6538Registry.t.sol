// SPDX-License-Identifier: UNLICENSED
pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import {Deploy} from "script/Deploy.s.sol";

contract ERC6538RegistryTest is Test, Deploy {
  function setUp() public {
    Deploy.run();
  }
}

contract RegisterKeys is ERC6538RegistryTest {
// TODO
}
