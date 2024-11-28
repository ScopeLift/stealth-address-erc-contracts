# ERC-5564 and ERC-6538 Contracts

This repo contains the canonical implementations of the ERC-5564 and ERC-6538 contracts:

- [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) Stealth Addresses: Private, non-interactive transfers and interactions.
- [ERC-6538](https://eips.ethereum.org/EIPS/eip-6538) Stealth Meta-Address Registry: A registry to map addresses to stealth meta-addresses

## Usage

This repo is developed using [Foundry](https://book.getfoundry.sh/).

### Setup

1. Install Foundry on your local machine by following the [instructions here](https://book.getfoundry.sh/getting-started/installation).

2. Clone the repo and navigate to the root directory of the repo:

```sh
git clone git@github.com:ScopeLift/stealth-address-erc-contracts.git
cd stealth-address-erc-contracts
```

### Compile

```sh
# Build the contracts
forge build
```

### Test

```sh
# Run the tests
forge test
```

### Coverage

```sh
# See test coverage
forge coverage
```

### Linting and Specifications

This project uses [scopelint](https://github.com/ScopeLift/scopelint) for linting and spec generation. Follow [these instructions](https://github.com/ScopeLift/scopelint?tab=readme-ov-file#installation) to install it.

#### Lint

```bash
# Check formatting
scopelint check
# Apply formatting changes
scopelint fmt
```

#### Spec

```bash
scopelint spec
```

This command will use the names of the contract's unit tests to generate a human readable spec. It will list each contract, its constituent functions, and the human readable description of functionality each unit test aims to assert.

## Deployments

The stealth contracts are deployed at the following addresses:

`ERC5564Announcer`: 0x55649E01B5Df198D18D95b5cc5051630cfD45564

`ERC6538Registry`: 0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538

_If you've deployed the contracts on networks other than the ones currently listed, please submit a pull request to update the deployment table with the relevant block scanner links. Thank you!_

### Mainnet Networks

| Networks     |                                                           ERC5564Announcer                                                            |                                                            ERC6538Registry                                                            |
| :----------- | :-----------------------------------------------------------------------------------------------------------------------------------: | :-----------------------------------------------------------------------------------------------------------------------------------: |
| Mainnet      |      [0x55649E01B5Df198D18D95b5cc5051630cfD45564](https://etherscan.io/address/0x55649E01B5Df198D18D95b5cc5051630cfD45564#code)       |      [0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538](https://etherscan.io/address/0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538#code)       |
| Arbitrum     |       [0x55649E01B5Df198D18D95b5cc5051630cfD45564](https://arbiscan.io/address/0x55649E01B5Df198D18D95b5cc5051630cfD45564#code)       |       [0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538](https://arbiscan.io/address/0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538#code)       |
| Base         |      [0x55649E01B5Df198D18D95b5cc5051630cfD45564](https://basescan.org/address/0x55649E01B5Df198D18D95b5cc5051630cfD45564#code)       |      [0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538](https://basescan.org/address/0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538#code)       |
| Gnosis Chain |      [0x55649E01B5Df198D18D95b5cc5051630cfD45564](https://gnosisscan.io/address/0x55649E01B5Df198D18D95b5cc5051630cfD45564#code)      |      [0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538](https://gnosisscan.io/address/0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538#code)      |
| Optimism     | [0x55649E01B5Df198D18D95b5cc5051630cfD45564](https://optimistic.etherscan.io/address/0x55649E01B5Df198D18D95b5cc5051630cfD45564#code) | [0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538](https://optimistic.etherscan.io/address/0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538#code) |
| Polygon      |     [0x55649E01B5Df198D18D95b5cc5051630cfD45564](https://polygonscan.com/address/0x55649E01B5Df198D18D95b5cc5051630cfD45564#code)     |     [0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538](https://polygonscan.com/address/0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538#code)     |
| Scroll       |     [0x55649E01B5Df198D18D95b5cc5051630cfD45564](https://scrollscan.com/address/0x55649E01B5Df198D18D95b5cc5051630cfD45564#code)      |     [0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538](https://scrollscan.com/address/0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538#code)      |

### Ethereum Test Networks

| Networks |                                                          ERC5564Announcer                                                          |                                                          ERC6538Registry                                                           |
| :------- | :--------------------------------------------------------------------------------------------------------------------------------: | :--------------------------------------------------------------------------------------------------------------------------------: |
| Sepolia  | [0x55649E01B5Df198D18D95b5cc5051630cfD45564](https://sepolia.etherscan.io/address/0x55649E01B5Df198D18D95b5cc5051630cfD45564#code) | [0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538](https://sepolia.etherscan.io/address/0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538#code) |
| Holešky  | [0x55649E01B5Df198D18D95b5cc5051630cfD45564](https://holesky.etherscan.io/address/0x55649E01B5Df198D18D95b5cc5051630cfD45564#code) | [0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538](https://holesky.etherscan.io/address/0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538#code) |

### Additional EVM-Based Test Networks

| Networks         |                                                              ERC5564Announcer                                                               |                                                               ERC6538Registry                                                               |
| :--------------- | :-----------------------------------------------------------------------------------------------------------------------------------------: | :-----------------------------------------------------------------------------------------------------------------------------------------: |
| Arbitrum Sepolia |      [0x55649E01B5Df198D18D95b5cc5051630cfD45564](https://sepolia.arbiscan.io/address/0x55649E01B5Df198D18D95b5cc5051630cfD45564#code)      |      [0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538](https://sepolia.arbiscan.io/address/0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538#code)      |
| Base Sepolia     |     [0x55649E01B5Df198D18D95b5cc5051630cfD45564](https://sepolia.basescan.org/address/0x55649E01B5Df198D18D95b5cc5051630cfD45564#code)      |     [0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538](https://sepolia.basescan.org/address/0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538#code)      |
| Optimism Sepolia | [0x55649E01B5Df198D18D95b5cc5051630cfD45564](https://sepolia-optimism.etherscan.io/address/0x55649E01B5Df198D18D95b5cc5051630cfD45564#code) | [0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538](https://sepolia-optimism.etherscan.io/address/0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538#code) |
| Odyssey Testnet  |    [0x55649E01B5Df198D18D95b5cc5051630cfD45564](https://odyssey-explorer.ithaca.xyz/address/0x55649E01B5Df198D18D95b5cc5051630cfD45564)     |    [0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538](https://odyssey-explorer.ithaca.xyz/address/0x6538E6bf4B0eBd30A8Ea093027Ac2422ce5d6538)     |

## Security

Coming soon.

## License

Contracts in this repository are released under the [MIT License](https://github.com/ScopeLift/stealth-address-erc-contracts/blob/main/LICENSE).
