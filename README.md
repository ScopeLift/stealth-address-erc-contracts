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

Coming soon.

## Security

Coming soon.

## License

Contracts in this repository are released under the [MIT License](https://github.com/ScopeLift/stealth-address-erc-contracts/blob/main/LICENSE).
