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
stellar-baselib = "0.8.0"
```

And this to your code:

```rust
use stellar_baselib::*;
```

## Envelope parsing migration (0.8.0)

This is an intentional breaking change for **0.8.0**, not a `0.7.x` patch.
See [MIGRATION.md](MIGRATION.md) for before/after examples, field-type changes,
builder defaults and release considerations.

`Transaction::from_xdr_envelope` now returns
`Result<ParsedTransaction, TransactionError>` instead of `Transaction`. It accepts
V0, V1 and fee-bump envelopes, and returns an error for invalid base64/XDR rather
than panicking.

```rust
use stellar_baselib::transaction::{ParsedTransaction, Transaction, TransactionBehavior};

# fn read(xdr: &str, network: &str) -> Result<(), Box<dyn std::error::Error>> {
match Transaction::from_xdr_envelope(xdr, network)? {
    ParsedTransaction::Transaction(tx) => println!("Fee: {}", tx.fee),
    ParsedTransaction::FeeBump(tx) => {
        println!("Outer fee: {}", tx.envelope().tx.fee);
        let inner = tx.inner_transaction();
        println!("Inner fee: {}", inner.fee);
    }
}
# Ok(())
# }
```

Callers that only accept ordinary transactions can use
`Transaction::from_xdr_envelope(xdr, network)?.into_transaction()?`; fee bumps
then produce `TransactionError::UnexpectedFeeBump`, rather than being silently
unwrapped. Fee-bump parsing preserves the complete signed XDR envelope.

Parsed V2 preconditions now retain sequence age as `Option<u64>` and extra signers
as `Option<Vec<xdr::SignerKey>>`, matching their protocol types. Minimum sequence
numbers are decimal strings, consistent with the transaction sequence field.

`ParsedTransaction::to_envelope()` handles every parsed variant without discarding
the outer fee bump. V0 serialization is constructed directly, and V1 serialization
preserves V2 preconditions (including an all-zero V2 discriminant), muxed accounts,
Soroban data, memos and signatures.

For mutable ordinary transactions, `try_to_envelope()`, `try_signature_base()` and
`try_hash()` return typed `TransactionError`s for invalid fields or exceeded XDR
bounds. Existing `to_envelope()` calls keep their boxed-error signature and now
return errors instead of panicking. Legacy infallible `signature_base()`/`hash()`
still panic on invalid mutable fields; use the `try_` alternatives for fallible
conversion. V0 conversion refuses unsupported muxed sources, V2 preconditions or
Soroban data rather than silently dropping them.

Builders now leave unused V2-only fields as `None`, instead of placeholder
`Some(0)`/empty values. Setting one of those fields explicitly selects V2;
newly built transactions otherwise retain their existing None/Time encoding.

## Fee-bump construction and signing (0.8.0)

`FeeBumpTransaction::new(fee_source, total_fee, inner_envelope, network, network_base_fee)`
wraps a signed V0 or V1 envelope without changing its signatures. V0 is normalized
to V1. The fee source may be a G-address or M-address and can differ from the
inner transaction source. Nested fee bumps are refused.

Both fees are in stroops: `total_fee` is an `i64` **total**, while
`network_base_fee` is the current ledger fee **per operation**, supplied by the
caller. The constructor checks:

```text
n = inner operation count
r = declared Soroban resource fee (zero for classic transactions)
minimum total = r + max(base_fee * (n + 1), ceil(max(inner.fee - r, 0) * (n + 1) / n))
```

An insufficient fee returns `FeeBumpError::InsufficientFee { fee, minimum }`.
Arithmetic overflow and invalid fee sources/inner structures also return typed
errors. Soroban rules target the current Protocol 23+ behavior: the outer
transaction can pay resource fees exceeding the inner transaction's `u32` fee.
Resource estimates and other network-state-dependent validity checks remain the
caller's responsibility. Meeting this minimum does not guarantee surge inclusion
or meet the separate 10x fee-rate requirement to replace a queued transaction.

```rust
use stellar_baselib::{
    account::{Account, AccountBehavior},
    asset::{Asset, AssetBehavior},
    fee_bump_transaction::FeeBumpTransaction,
    keypair::{Keypair, KeypairBehavior},
    network::{NetworkPassphrase, Networks},
    operation::Operation,
    transaction::TransactionBehavior,
    transaction_builder::{TransactionBuilder, TransactionBuilderBehavior},
};

# fn example() -> Result<(), Box<dyn std::error::Error>> {
// Test-only keys; real accounts must already exist and have sufficient balance.
let source_key = Keypair::from_raw_ed25519_seed(&[1; 32])?;
let payer = Keypair::from_raw_ed25519_seed(&[2; 32])?;
let mut source = Account::new(&source_key.public_key(), "0")?;
let mut inner = TransactionBuilder::new(&mut source, Networks::testnet(), None)
    .fee(100_u32)
    .add_operation(Operation::new().payment(&payer.public_key(), &Asset::native(), 1)?)
    .set_timeout(300)?
    .build();
inner.sign(&[source_key]);
let mut bump = FeeBumpTransaction::new(
    &payer.public_key(), 200, inner.to_envelope()?, Networks::testnet(), 100,
)?;
bump.sign(&[payer])?;
let signed_envelope = bump.to_envelope();
let outer_hash = bump.hash()?;
let inner_hash = bump.inner_hash()?;
# Ok(())
# }
```

`sign` adds only outer signatures and is atomic on failure (including a public-only
key or more than twenty signatures). Hashes are computed from their respective
network-specific signature payloads, not from the signed envelope bytes.
Both `inner_envelope()` and `inner_transaction().try_to_envelope()` preserve the
signed inner transaction. Submission is provided by `soroban-client` 0.8.0;
this base crate does not perform network I/O.

## Protocol Compatibility

| `stellar-baselib` version | Stellar Protocol Number | `stellar-xdr` | `stellar-strkey` |
| ------------------------- | ----------------------- | ------------- | ---------------- |
| `0.8.x`                   | Protocol 30             | `30.0.0`      | `1.0.0`          |
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
