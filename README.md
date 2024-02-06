# ERC-5564 and ERC-6538 Contracts

This repo contains the canonical implementations of the ERC-5564 and ERC-6538 contracts:

- [ERC-5564](https://eips.ethereum.org/EIPS/eip-5564) Stealth Addresses: Private, non-interactive transfers and interactions.
- [ERC-6538](https://eips.ethereum.org/EIPS/eip-6538) Stealth Meta-Address Registry: A registry to map addresses to stealth meta-addresses

## Usage

This repo is developed using [Foundry](https://book.getfoundry.sh/).

### Setup

1. Install [Foundry](https://book.getfoundry.sh/getting-started/installation) on your local machine by opening the terminal and running the following command:

```sh
curl -L https://foundry.paradigm.xyz | bash
```

2. Clone the repo and navigate to the root directory of the repo.

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

### Specifications

#### Pre-requisites

1. Install the [rust toolchain](https://www.rust-lang.org/tools/install).
2. Run `cargo install scopelint`

#### See contract specifications

```sh
scopelint spec
```

## Deployments

## Security

## License

Contracts in this repository are released under the [MIT License](https://github.com/ScopeLift/stealth-address-erc-contracts/blob/main/LICENSE).
