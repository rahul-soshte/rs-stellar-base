# Stellar Base Library

![Crates.io](https://img.shields.io/crates/v/stellar-baselib)
![Crates.io](https://img.shields.io/crates/l/stellar-baselib)
![Crates.io](https://img.shields.io/crates/d/stellar-baselib)

A library that offers a comprehensive set of functions for reading, writing, hashing, and signing primitive XDR constructs utilized in the Stellar network. it provides a nice abstraction for building and signing transactions

**This project is currently production and is compatible with Protocol 30 and you can use it for buidling and signing transactions that involve interacting with Soroban and also supports all stellar classic operations.**

## Quickstart

Add this to your Cargo.toml:

```toml
[dependencies]
stellar-baselib = "0.7.0"
```

And this to your code:

```rust
use stellar_baselib::*;
```

## Protocol Compatibility

| `stellar-baselib` version | Stellar Protocol Number | `stellar-xdr` | `stellar-strkey` |
| ------------------------- | ----------------------- | ------------- | ---------------- |
| `0.7.x`                   | Protocol 30             | `30.0.0`      | `1.0.0`          |
| `0.6.x`                   | Protocol 28             | `28.0.0`      | `0.0.15`         |

## Protocol 30

Uses `stellar-xdr 30` and `stellar-strkey 1`. `Address` supports muxed contract
addresses (`W...`) for muxed address parameters. Ledger close-time fields and
transaction time bounds remain in seconds.

## Signing and verifying messages (SEP-53)

`Keypair` signs and verifies arbitrary off-chain messages as defined in
[SEP-53](https://github.com/stellar/stellar-protocol/blob/master/ecosystem/sep-0053.md),
matching `Keypair.signMessage` / `Keypair.verifyMessage` in the JS and Java SDKs.
The message is prefixed with `"Stellar Signed Message:\n"`, hashed with SHA-256
and signed with ed25519. Strings are signed as UTF-8; byte slices as-is.

```rust
use stellar_baselib::keypair::{Keypair, KeypairBehavior};

let signer = Keypair::from_secret("SAKICEVQLYWGSOJS4WW7HZJWAHZVEEBS527LHK5V4MLJALYKICQCJXMW").unwrap();
let signature = signer.sign_message("Hello, World!").unwrap(); // 64 bytes

// A service only needs the account's public key to check the claim.
let verifier = Keypair::from_public_key("GBXFXNDLV4LSWA4VB7YIL5GBD7BVNR22SGBTDKMO2SBZZHDXSKZYCP7L").unwrap();
assert!(verifier.verify_message("Hello, World!", &signature));
```

A valid signature proves control of the key, not of the account: an account
with multiple signers, or whose master key weight is 0, is not controlled by
this key alone.

## How to run tests

```bash
cargo test
```

## Coding Best Practices Used

1. All Rust code is linted with Clippy with the command `cargo clippy`. If preferred to ignore its advice, do so explicitly:
   `#[allow(clippy::too_many_arguments)]`

2. All rust code is formatted with `cargo fmt`. rustfmt.toml defines the expected format.

3. Function and local variable names follow snake_case. Structs or Enums follow CamelCase and Constants have all capital letters.
