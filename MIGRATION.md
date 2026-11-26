# Migrating stellar-baselib from 0.7.x to 0.8.0

0.8.0 is the breaking release boundary for fee-bump support. It continues to use
Protocol 30 XDR; the version change is an SDK API change, not a protocol upgrade.

```toml
[dependencies]
stellar-baselib = "0.8.0"
```

## Envelope parsing is fallible and returns either transaction kind

Before (0.7.x):

```rust,ignore
let tx: Transaction = Transaction::from_xdr_envelope(encoded, network);
```

After (0.8.0), if the application only accepts ordinary V0/V1 transactions:

```rust
use stellar_baselib::transaction::{Transaction, TransactionBehavior, TransactionError};

fn read_ordinary(encoded: &str, network: &str) -> Result<Transaction, TransactionError> {
    Transaction::from_xdr_envelope(encoded, network)?.into_transaction()
}
```

Malformed base64/XDR returns `InvalidEnvelope`. A valid fee bump produces
`UnexpectedFeeBump` when explicitly selecting an ordinary transaction; it is not
silently unwrapped. Applications accepting both types should match the enum:

```rust
use stellar_baselib::transaction::{ParsedTransaction, Transaction, TransactionBehavior, TransactionError};
use stellar_baselib::xdr::TransactionEnvelope;

fn read_envelope(encoded: &str, network: &str) -> Result<TransactionEnvelope, TransactionError> {
    let parsed = Transaction::from_xdr_envelope(encoded, network)?;
    match &parsed {
        ParsedTransaction::Transaction(tx) => println!("Ordinary fee: {}", tx.fee),
        ParsedTransaction::FeeBump(tx) => println!("Outer fee: {}", tx.envelope().tx.fee),
    }
    parsed.to_envelope()
}
```

Custom implementations of `TransactionBehavior` must also change their
`from_xdr_envelope` signature from `-> Self` to
`-> Result<ParsedTransaction, TransactionError>`. This trait method is deliberately
breaking; there is no retained legacy parser that panics on fee bumps.

## Corrected public transaction field types

| Field | 0.7.x | 0.8.0 |
| --- | --- | --- |
| `min_account_sequence_age` | `Option<u32>` | `Option<u64>` |
| `extra_signers` | `Option<Vec<xdr::AccountId>>` | `Option<Vec<xdr::SignerKey>>` |

Widen explicitly typed ages with `u64::from(age)`. Extra signers are signer keys,
not accounts; this supports the other signer kinds that valid V2 XDR can contain.
For an existing Ed25519 account ID:

```rust
use stellar_baselib::xdr::{AccountId, PublicKey, SignerKey};

fn account_signer(account: AccountId) -> SignerKey {
    let PublicKey::PublicKeyTypeEd25519(key) = account.0;
    SignerKey::Ed25519(key)
}
```

Parsed `min_account_sequence` values are now decimal strings, consistent with
`sequence`, not base64-encoded sequence numbers. Update code that decoded those
values as base64. Struct literals, wrappers and conversion code using the old
field types must be updated.

## Builder defaults and faithful preconditions

Unused V2-only fields now start as `None`, replacing placeholder `Some("0")`,
`Some(0)` and empty signer vectors. Ordinary builder output retains its previous
None/Time precondition encoding unless ledger bounds or V2 fields are set.

Setting any V2-only field explicitly, including `Some(0)` or `Some(vec![])`,
selects V2. Parsing preserves an all-zero V2 as V2, rather than collapsing it to
None/Time. To clear V2, clear all V2-only fields (including ledger bounds).

V0 serialization now constructs V0 XDR directly. It rejects muxed sources,
V2 preconditions and Soroban data rather than silently dropping unsupported
fields. Parsed signatures, transaction extensions and signing hashes survive
round trips. Hashes may differ from 0.7.x when that version incorrectly dropped
or reset fields; never reuse signatures after intentionally changing contents.

## Existing APIs and fallible alternatives

Ordinary builders, `sign`, `signature_base`, `hash` and the boxed-error
`to_envelope` retain their signatures. Prefer the new typed fallible methods when
handling mutable or untrusted transaction fields:

- `try_to_envelope() -> Result<TransactionEnvelope, TransactionError>`
- `try_signature_base() -> Result<Vec<u8>, TransactionError>`
- `try_hash() -> Result<[u8; 32], TransactionError>`

Legacy infallible hash/signing methods can still panic on invalid mutable fields
or signing keys. The fallible methods do not change that legacy contract.

Fee bumps are a separate `FeeBumpTransaction` type with an `i64` total fee.
`Transaction::fee` remains `u32`; existing ordinary callers do not need to widen
their fee fields. The fee-bump constructor requires an explicit fee source and
network base-fee snapshot. Its minimum-fee check does not guarantee surge
inclusion or queued-transaction replacement.

