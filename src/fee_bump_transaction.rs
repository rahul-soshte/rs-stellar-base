//! Fee-bump transactions ([CAP-15]).
//!
//! A fee-bump transaction wraps an already-signed transaction and pays its fee from a
//! different account (the *fee source*). The inner transaction keeps its own source,
//! sequence number, operations and signatures; the fee bump only adds a fee source, a
//! new (higher) fee, and the fee source's signatures.
//!
//! Use [`FeeBumpTransaction::new`] (or the equivalent
//! [`TransactionBuilder::build_fee_bump_transaction`]) to wrap a transaction, and
//! [`GenericTransaction::from_xdr_envelope`] to parse an envelope that may be either kind.
//!
//! [CAP-15]: https://github.com/stellar/stellar-protocol/blob/master/core/cap-0015.md
//! [`TransactionBuilder::build_fee_bump_transaction`]: crate::transaction_builder::TransactionBuilder::build_fee_bump_transaction

use std::fmt;
use std::str::FromStr;

use crate::hashing::{HashingBehavior, Sha256Hasher};
use crate::keypair::{Keypair, KeypairBehavior};
use crate::transaction::{Transaction, TransactionBehavior};
use crate::transaction_builder::BASE_FEE;
use crate::utils::decode_encode_muxed_account::encode_muxed_account_to_address;
use crate::xdr::{self, Limits, ReadXdr, WriteXdr};

/// Errors from building, signing or parsing a [`FeeBumpTransaction`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FeeBumpError {
    /// The per-operation base fee is below what the network accepts for this fee bump.
    ///
    /// A fee bump must pay at least the network minimum ([`BASE_FEE`]) per operation,
    /// and at least the inner transaction's inclusion-fee rate. `minimum` is the
    /// smallest `base_fee` that satisfies both.
    BaseFeeTooLow {
        /// The base fee that was requested.
        base_fee: i64,
        /// The smallest base fee the network would accept.
        minimum: i64,
    },
    /// The fee source is not a valid `G...` or `M...` account address.
    InvalidFeeSource(String),
    /// The inner transaction could not be turned into an envelope.
    InvalidInnerTransaction(String),
    /// The inner transaction has no operations.
    EmptyInnerTransaction,
    /// The total fee does not fit in an `i64`.
    FeeOverflow,
    /// Adding the signatures would exceed the protocol limit of 20 per envelope.
    TooManySignatures,
    /// The base64 input is not a valid XDR transaction envelope.
    InvalidXdr(String),
    /// The envelope is valid but is not a fee-bump envelope.
    NotFeeBump(xdr::EnvelopeType),
}

impl fmt::Display for FeeBumpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BaseFeeTooLow { base_fee, minimum } => write!(
                f,
                "invalid base fee {base_fee}: it should be at least {minimum} stroops"
            ),
            Self::InvalidFeeSource(source) => write!(f, "invalid fee source: {source}"),
            Self::InvalidInnerTransaction(reason) => {
                write!(f, "invalid inner transaction: {reason}")
            }
            Self::EmptyInnerTransaction => write!(f, "inner transaction has no operations"),
            Self::FeeOverflow => write!(f, "fee-bump fee overflows i64"),
            Self::TooManySignatures => {
                write!(f, "a transaction envelope holds at most 20 signatures")
            }
            Self::InvalidXdr(reason) => write!(f, "invalid transaction envelope XDR: {reason}"),
            Self::NotFeeBump(kind) => {
                write!(f, "expected a fee-bump envelope, got {}", kind.name())
            }
        }
    }
}

impl std::error::Error for FeeBumpError {}

/// A fee-bump transaction: an inner, already-signed transaction plus a fee source that
/// pays a higher fee for it.
///
/// The XDR is the source of truth. The inner envelope is kept exactly as it was
/// received or built, so the inner signatures and the inner hash are preserved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeeBumpTransaction {
    network_passphrase: String,
    envelope: xdr::FeeBumpTransactionEnvelope,
}

impl FeeBumpTransaction {
    /// Wrap `inner_tx` in a fee bump paid by `fee_source`.
    ///
    /// - `fee_source`: the account paying the fee, as a `G...` or muxed `M...` address.
    /// - `base_fee`: the fee per operation, in stroops. The fee bump counts as one extra
    ///   operation, so the total fee is `base_fee * (inner operations + 1)`, plus the
    ///   inner transaction's Soroban resource fee if it has one.
    /// - `inner_tx`: the transaction to wrap. It should already be signed by its source.
    ///
    /// The network passphrase is taken from `inner_tx`, because the fee bump has to be
    /// signed for the same network as the transaction it wraps.
    ///
    /// The network's minimum-fee rule is checked here. `base_fee` must be at least
    /// [`BASE_FEE`] and at least the inner transaction's inclusion fee per operation
    /// (its fee minus any Soroban resource fee). Otherwise this returns
    /// [`FeeBumpError::BaseFeeTooLow`] with the smallest base fee that would be accepted.
    ///
    /// A `TxV0` inner transaction is converted to the equivalent `Tx` (v1) envelope. Its
    /// hash and signatures stay valid.
    pub fn new(
        fee_source: &str,
        base_fee: i64,
        inner_tx: &Transaction,
    ) -> Result<Self, FeeBumpError> {
        let inner_envelope = match inner_tx
            .to_envelope()
            .map_err(|e| FeeBumpError::InvalidInnerTransaction(e.to_string()))?
        {
            xdr::TransactionEnvelope::Tx(v1) => v1,
            xdr::TransactionEnvelope::TxV0(v0) => v0_to_v1(v0),
            xdr::TransactionEnvelope::TxFeeBump(_) => {
                return Err(FeeBumpError::InvalidInnerTransaction(
                    "a fee-bump transaction cannot be wrapped in another fee bump".into(),
                ))
            }
        };

        let fee_source_account = xdr::MuxedAccount::from_str(fee_source)
            .map_err(|_| FeeBumpError::InvalidFeeSource(fee_source.to_owned()))?;

        let fee = fee_bump_fee(&inner_envelope.tx, base_fee)?;

        Ok(Self {
            network_passphrase: inner_tx.network_passphrase.clone(),
            envelope: xdr::FeeBumpTransactionEnvelope {
                tx: xdr::FeeBumpTransaction {
                    fee_source: fee_source_account,
                    fee,
                    inner_tx: xdr::FeeBumpTransactionInnerTx::Tx(inner_envelope),
                    ext: xdr::FeeBumpTransactionExt::V0,
                },
                signatures: xdr::VecM::default(),
            },
        })
    }

    /// Parse a base64 XDR envelope that must be a fee bump.
    ///
    /// Use [`GenericTransaction::from_xdr_envelope`] when the envelope may be either kind.
    pub fn from_xdr_envelope(xdr: &str, network_passphrase: &str) -> Result<Self, FeeBumpError> {
        let envelope = xdr::TransactionEnvelope::from_xdr_base64(xdr, Limits::none())
            .map_err(|e| FeeBumpError::InvalidXdr(e.to_string()))?;
        Self::from_envelope(envelope, network_passphrase)
    }

    /// Build from a decoded envelope that must be a fee bump.
    pub fn from_envelope(
        envelope: xdr::TransactionEnvelope,
        network_passphrase: &str,
    ) -> Result<Self, FeeBumpError> {
        match envelope {
            xdr::TransactionEnvelope::TxFeeBump(envelope) => Ok(Self {
                network_passphrase: network_passphrase.to_owned(),
                envelope,
            }),
            other => Err(FeeBumpError::NotFeeBump(other.discriminant())),
        }
    }

    /// The network passphrase this fee bump is signed for.
    pub fn network_passphrase(&self) -> &str {
        &self.network_passphrase
    }

    /// The fee source as a `G...` address, or an `M...` address if it is muxed.
    pub fn fee_source(&self) -> String {
        encode_muxed_account_to_address(&self.envelope.tx.fee_source)
    }

    /// The fee source as XDR.
    pub fn fee_source_account(&self) -> &xdr::MuxedAccount {
        &self.envelope.tx.fee_source
    }

    /// The maximum total fee, in stroops, the fee source pays.
    pub fn fee(&self) -> i64 {
        self.envelope.tx.fee
    }

    /// The wrapped envelope, exactly as it will be submitted.
    pub fn inner_envelope(&self) -> &xdr::TransactionV1Envelope {
        let xdr::FeeBumpTransactionInnerTx::Tx(inner) = &self.envelope.tx.inner_tx;
        inner
    }

    /// The wrapped transaction, decoded into a [`Transaction`].
    pub fn inner_transaction(&self) -> Transaction {
        Transaction::from_envelope(
            xdr::TransactionEnvelope::Tx(self.inner_envelope().clone()),
            &self.network_passphrase,
        )
    }

    /// Hash of the inner transaction, computed from its XDR.
    pub fn inner_transaction_hash(&self) -> [u8; 32] {
        let payload = xdr::TransactionSignaturePayload {
            network_id: self.network_id(),
            tagged_transaction: xdr::TransactionSignaturePayloadTaggedTransaction::Tx(
                self.inner_envelope().tx.clone(),
            ),
        };
        Sha256Hasher::hash(
            payload
                .to_xdr(Limits::none())
                .expect("in-memory XDR encoding cannot fail"),
        )
    }

    /// The fee source's signatures. The inner transaction's signatures are on
    /// [`inner_envelope`](Self::inner_envelope).
    pub fn signatures(&self) -> &[xdr::DecoratedSignature] {
        &self.envelope.signatures
    }

    /// The bytes that get hashed and signed. The payload is tagged `TxFeeBump`.
    pub fn signature_base(&self) -> Vec<u8> {
        xdr::TransactionSignaturePayload {
            network_id: self.network_id(),
            tagged_transaction: xdr::TransactionSignaturePayloadTaggedTransaction::TxFeeBump(
                self.envelope.tx.clone(),
            ),
        }
        .to_xdr(Limits::none())
        .expect("in-memory XDR encoding cannot fail")
    }

    /// The fee-bump transaction hash. Once submitted, the network reports the
    /// transaction under this hash, not the inner one.
    pub fn hash(&self) -> [u8; 32] {
        Sha256Hasher::hash(self.signature_base())
    }

    /// Sign with each keypair. Normally that is the fee source, or the fee source's
    /// signers if it is a multisig account.
    pub fn sign(&mut self, keypairs: &[Keypair]) -> Result<(), FeeBumpError> {
        let hash = self.hash();
        let mut signatures = self.envelope.signatures.to_vec();
        signatures.extend(keypairs.iter().map(|kp| kp.sign_decorated(&hash)));
        self.envelope.signatures = signatures
            .try_into()
            .map_err(|_| FeeBumpError::TooManySignatures)?;
        Ok(())
    }

    /// The envelope to submit to the network.
    pub fn to_envelope(&self) -> xdr::TransactionEnvelope {
        xdr::TransactionEnvelope::TxFeeBump(self.envelope.clone())
    }

    /// The envelope as base64 XDR.
    pub fn to_xdr_base64(&self) -> String {
        self.to_envelope()
            .to_xdr_base64(Limits::none())
            .expect("in-memory XDR encoding cannot fail")
    }

    fn network_id(&self) -> xdr::Hash {
        xdr::Hash(Sha256Hasher::hash(self.network_passphrase.as_bytes()))
    }
}

impl From<FeeBumpTransaction> for xdr::TransactionEnvelope {
    fn from(tx: FeeBumpTransaction) -> Self {
        xdr::TransactionEnvelope::TxFeeBump(tx.envelope)
    }
}

impl fmt::Display for FeeBumpTransaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "FeeBumpTransaction {{")?;
        writeln!(f, "  Network: {}", self.network_passphrase)?;
        writeln!(f, "  Fee Source: {}", self.fee_source())?;
        writeln!(f, "  Fee: {}", self.fee())?;
        writeln!(
            f,
            "  Inner Transaction Hash: {}",
            hex::encode(self.inner_transaction_hash())
        )?;
        writeln!(f, "  Signatures: {}", self.signatures().len())?;
        write!(f, "}}")
    }
}

/// Either a regular [`Transaction`] or a [`FeeBumpTransaction`].
///
/// This is what you get when you parse an envelope whose kind you don't know in
/// advance. Use it wherever either kind is accepted, for example when submitting.
#[derive(Debug, Clone)]
pub enum GenericTransaction {
    /// A `TxV0` or `Tx` envelope.
    Transaction(Transaction),
    /// A `TxFeeBump` envelope.
    FeeBump(FeeBumpTransaction),
}

impl GenericTransaction {
    /// Parse a base64 XDR envelope of any kind. This never panics. Invalid input
    /// returns an error.
    pub fn from_xdr_envelope(xdr: &str, network_passphrase: &str) -> Result<Self, FeeBumpError> {
        let envelope = xdr::TransactionEnvelope::from_xdr_base64(xdr, Limits::none())
            .map_err(|e| FeeBumpError::InvalidXdr(e.to_string()))?;
        Ok(Self::from_envelope(envelope, network_passphrase))
    }

    /// Build from a decoded envelope of any kind.
    pub fn from_envelope(envelope: xdr::TransactionEnvelope, network_passphrase: &str) -> Self {
        match envelope {
            xdr::TransactionEnvelope::TxFeeBump(envelope) => Self::FeeBump(FeeBumpTransaction {
                network_passphrase: network_passphrase.to_owned(),
                envelope,
            }),
            other => Self::Transaction(Transaction::from_envelope(other, network_passphrase)),
        }
    }

    /// The regular transaction, if this is one.
    pub fn as_transaction(&self) -> Option<&Transaction> {
        match self {
            Self::Transaction(tx) => Some(tx),
            Self::FeeBump(_) => None,
        }
    }

    /// The fee bump, if this is one.
    pub fn as_fee_bump(&self) -> Option<&FeeBumpTransaction> {
        match self {
            Self::FeeBump(tx) => Some(tx),
            Self::Transaction(_) => None,
        }
    }

    /// The hash the network reports this transaction under.
    pub fn hash(&self) -> [u8; 32] {
        match self {
            Self::Transaction(tx) => tx.hash(),
            Self::FeeBump(tx) => tx.hash(),
        }
    }

    /// The envelope to submit to the network.
    pub fn to_envelope(&self) -> Result<xdr::TransactionEnvelope, Box<dyn std::error::Error>> {
        match self {
            Self::Transaction(tx) => tx.to_envelope(),
            Self::FeeBump(tx) => Ok(tx.to_envelope()),
        }
    }
}

impl From<Transaction> for GenericTransaction {
    fn from(tx: Transaction) -> Self {
        Self::Transaction(tx)
    }
}

impl From<FeeBumpTransaction> for GenericTransaction {
    fn from(tx: FeeBumpTransaction) -> Self {
        Self::FeeBump(tx)
    }
}

/// Total fee for a fee bump over `inner`, after checking the minimum-fee rule.
///
/// stellar-core accepts a fee bump when both of these hold:
/// - its inclusion fee is at least `BASE_FEE * (ops + 1)`, and
/// - its inclusion-fee rate is at least the inner transaction's rate, i.e.
///   `bump_inclusion * ops >= inner_inclusion * (ops + 1)`.
///
/// With `bump_inclusion = base_fee * (ops + 1)`, the second becomes
/// `base_fee * ops >= inner_inclusion`, which is checked here in integers.
/// The Soroban resource fee is not part of either inclusion fee. It is carried over
/// unchanged on top.
fn fee_bump_fee(inner: &xdr::Transaction, base_fee: i64) -> Result<i64, FeeBumpError> {
    let ops = inner.operations.len() as i64;
    if ops == 0 {
        return Err(FeeBumpError::EmptyInnerTransaction);
    }

    let resource_fee = match &inner.ext {
        xdr::TransactionExt::V1(data) => data.resource_fee,
        xdr::TransactionExt::V0 => 0,
    };
    let inner_inclusion_fee = i64::from(inner.fee) - resource_fee;
    // Smallest base fee with base_fee * ops >= inner_inclusion_fee (ceiling division).
    let inner_rate = if inner_inclusion_fee > 0 {
        (inner_inclusion_fee + ops - 1) / ops
    } else {
        0
    };
    let minimum = inner_rate.max(i64::from(BASE_FEE));

    if base_fee < minimum {
        return Err(FeeBumpError::BaseFeeTooLow { base_fee, minimum });
    }

    base_fee
        .checked_mul(ops + 1)
        .and_then(|fee| fee.checked_add(resource_fee))
        .ok_or(FeeBumpError::FeeOverflow)
}

/// Convert a `TxV0` envelope to the equivalent `Tx` envelope. Both have the same hash,
/// so the existing signatures stay valid.
fn v0_to_v1(v0: xdr::TransactionV0Envelope) -> xdr::TransactionV1Envelope {
    let tx = v0.tx;
    xdr::TransactionV1Envelope {
        tx: xdr::Transaction {
            source_account: xdr::MuxedAccount::Ed25519(tx.source_account_ed25519),
            fee: tx.fee,
            seq_num: tx.seq_num,
            cond: tx
                .time_bounds
                .map_or(xdr::Preconditions::None, xdr::Preconditions::Time),
            memo: tx.memo,
            operations: tx.operations,
            ext: xdr::TransactionExt::V0,
        },
        signatures: v0.signatures,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::account::{Account, AccountBehavior};
    use crate::asset::{Asset, AssetBehavior};
    use crate::network::{NetworkPassphrase, Networks};
    use crate::operation::{self, Operation};
    use crate::soroban_data_builder::{SorobanDataBuilder, SorobanDataBuilderBehavior};
    use crate::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};

    fn inner_keypair() -> Keypair {
        Keypair::from_raw_ed25519_seed(&[1u8; 32]).unwrap()
    }

    fn fee_keypair() -> Keypair {
        Keypair::from_raw_ed25519_seed(&[2u8; 32]).unwrap()
    }
    const DESTINATION: &str = "GDJJRRMBK4IWLEPJGIE6SXD2LP7REGZODU7WDC3I2D6MR37F4XSHBKX2";

    fn signed_inner(fee_per_op: u32, ops: usize) -> (Transaction, Keypair) {
        let kp = inner_keypair();
        let mut account = Account::new(&kp.public_key(), "1234").unwrap();
        let mut builder = TransactionBuilder::new(&mut account, Networks::testnet(), None);
        builder.fee(fee_per_op);
        for _ in 0..ops {
            builder.add_operation(
                Operation::new()
                    .payment(DESTINATION, &Asset::native(), operation::ONE)
                    .unwrap(),
            );
        }
        let mut tx = builder.build();
        tx.sign(std::slice::from_ref(&kp));
        (tx, kp)
    }

    #[test]
    fn builds_signs_and_verifies_fee_bump_from_different_source() {
        let (inner, inner_kp) = signed_inner(100, 2);
        let fee_kp = fee_keypair();
        assert_ne!(inner_kp.public_key(), fee_kp.public_key());

        let mut fb = FeeBumpTransaction::new(&fee_kp.public_key(), 300, &inner).unwrap();
        assert_eq!(fb.fee(), 300 * 3);
        assert_eq!(fb.fee_source(), fee_kp.public_key());
        assert_eq!(fb.network_passphrase(), Networks::testnet());
        assert_eq!(fb.inner_transaction_hash(), inner.hash());
        assert_eq!(fb.inner_envelope().signatures.len(), 1);
        assert_ne!(fb.hash(), inner.hash());

        fb.sign(std::slice::from_ref(&fee_kp)).unwrap();
        assert_eq!(fb.signatures().len(), 1);
        assert!(fee_kp.verify(&fb.hash(), &fb.signatures()[0].signature.0));

        // The signature payload is tagged TxFeeBump.
        let payload =
            xdr::TransactionSignaturePayload::from_xdr(fb.signature_base(), Limits::none())
                .unwrap();
        assert!(matches!(
            payload.tagged_transaction,
            xdr::TransactionSignaturePayloadTaggedTransaction::TxFeeBump(_)
        ));

        // Same thing via the JS-style builder entry point.
        let via_builder =
            TransactionBuilder::build_fee_bump_transaction(&fee_kp.public_key(), 300, &inner)
                .unwrap();
        assert_eq!(
            via_builder.hash(),
            FeeBumpTransaction::new(&fee_kp.public_key(), 300, &inner)
                .unwrap()
                .hash()
        );
    }

    #[test]
    fn round_trips_through_base64_and_recovers_inner_transaction() {
        let (inner, _) = signed_inner(100, 1);
        let fee_kp = fee_keypair();
        let mut fb = FeeBumpTransaction::new(&fee_kp.public_key(), 200, &inner).unwrap();
        fb.sign(&[fee_kp]).unwrap();

        let b64 = fb.to_xdr_base64();
        let parsed = FeeBumpTransaction::from_xdr_envelope(&b64, Networks::testnet()).unwrap();
        assert_eq!(parsed, fb);
        assert_eq!(parsed.hash(), fb.hash());
        assert_eq!(parsed.to_xdr_base64(), b64);

        let recovered = parsed.inner_transaction();
        assert_eq!(recovered.hash(), inner.hash());
        assert_eq!(recovered.source, inner.source);
        assert_eq!(recovered.sequence, inner.sequence);
        assert_eq!(recovered.operations, inner.operations);
        assert_eq!(recovered.signatures, inner.signatures);
    }

    #[test]
    fn rejects_base_fee_below_network_minimum() {
        let (inner, _) = signed_inner(100, 1);
        let fee_source = fee_keypair().public_key();
        assert_eq!(
            FeeBumpTransaction::new(&fee_source, 99, &inner),
            Err(FeeBumpError::BaseFeeTooLow {
                base_fee: 99,
                minimum: 100
            })
        );
        assert!(FeeBumpTransaction::new(&fee_source, 100, &inner).is_ok());
    }

    #[test]
    fn rejects_base_fee_below_inner_fee_rate() {
        // Inner pays 500 per op over 2 ops; the fee bump must pay at least 500 per op.
        let (inner, _) = signed_inner(500, 2);
        let fee_source = fee_keypair().public_key();
        let err = FeeBumpTransaction::new(&fee_source, 499, &inner).unwrap_err();
        assert_eq!(
            err,
            FeeBumpError::BaseFeeTooLow {
                base_fee: 499,
                minimum: 500
            }
        );
        assert!(err.to_string().contains("at least 500"));
        assert_eq!(
            FeeBumpTransaction::new(&fee_source, 500, &inner)
                .unwrap()
                .fee(),
            1500
        );
    }

    #[test]
    fn excludes_soroban_resource_fee_from_rate_and_carries_it_over() {
        let kp = inner_keypair();
        let mut account = Account::new(&kp.public_key(), "1").unwrap();
        let soroban_data = SorobanDataBuilder::new(None)
            .set_refundable_fee(50_000)
            .build();
        let mut inner = TransactionBuilder::new(&mut account, Networks::testnet(), None)
            .fee(50_100_u32) // 100 inclusion + 50_000 resource
            .add_operation(
                Operation::new()
                    .payment(DESTINATION, &Asset::native(), operation::ONE)
                    .unwrap(),
            )
            .set_soroban_data(soroban_data)
            .build();
        inner.sign(&[kp]);

        let fee_source = fee_keypair().public_key();
        // 100 is enough: the resource fee doesn't count toward the inclusion rate.
        let fb = FeeBumpTransaction::new(&fee_source, 100, &inner).unwrap();
        assert_eq!(fb.fee(), 100 * 2 + 50_000);
        assert_eq!(fb.inner_transaction_hash(), inner.hash());
        // The inner Soroban data survives recovery, so its hash still matches.
        let recovered = fb.inner_transaction();
        assert!(recovered.soroban_data.is_some());
        assert_eq!(recovered.hash(), inner.hash());
    }

    #[test]
    fn wraps_v0_inner_as_v1_with_same_hash() {
        // TxV0 envelope from js-stellar-sdk issue #73 fixture style (public network).
        let v0 = "AAAAAAtjwtJadppTmm0NtAU99BFxXXfzPO1N/SqR43Z8aXqXAAAAZAAIj6YAAAACAAAAAAAAAAEAAAAB0QAAAAAAAAEAAAAAAAAAAQAAAADLa6390PDAqg3qDLpshQxS+uVw3ytSgKRirQcInPWt1QAAAAAAAAAAA1Z+AAAAAAAAAAABfGl6lwAAAEBC655+8Izq54MIZrXTVF/E1ycHgQWpVcBD+LFkuOjjJd995u/7wM8sFqQqambL0/ME2FTOtxMO65B9i3eAIu4P";
        let inner = Transaction::from_xdr_envelope(v0, Networks::public());
        assert_eq!(inner.envelope_type, xdr::EnvelopeType::TxV0);

        let fee_source = fee_keypair().public_key();
        let fb = FeeBumpTransaction::new(&fee_source, 100, &inner).unwrap();
        assert_eq!(
            hex::encode(fb.inner_transaction_hash()),
            "a84d534b3742ad89413bdbf259e02fa4c5d039123769e9bcc63616f723a2bcd5"
        );
        assert_eq!(fb.inner_envelope().signatures.len(), 1);
    }

    #[test]
    fn accepts_muxed_fee_source() {
        let (inner, _) = signed_inner(100, 1);
        let muxed = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAACJUQ";
        let fb = FeeBumpTransaction::new(muxed, 100, &inner).unwrap();
        assert_eq!(fb.fee_source(), muxed);
        assert!(matches!(
            fb.fee_source_account(),
            xdr::MuxedAccount::MuxedEd25519(_)
        ));
    }

    #[test]
    fn rejects_invalid_fee_source_and_nested_fee_bump() {
        let (inner, _) = signed_inner(100, 1);
        assert_eq!(
            FeeBumpTransaction::new("not-an-address", 100, &inner),
            Err(FeeBumpError::InvalidFeeSource("not-an-address".into()))
        );
    }

    #[test]
    fn sign_rejects_more_than_twenty_signatures() {
        let (inner, _) = signed_inner(100, 1);
        let fee_kp = fee_keypair();
        let mut fb = FeeBumpTransaction::new(&fee_kp.public_key(), 100, &inner).unwrap();
        fb.sign(&vec![fee_kp.clone(); 20]).unwrap();
        assert_eq!(fb.sign(&[fee_kp]), Err(FeeBumpError::TooManySignatures));
        assert_eq!(fb.signatures().len(), 20);
    }

    // One parse test per envelope variant: none of them may panic.

    const TX_V0: &str = "AAAAAAtjwtJadppTmm0NtAU99BFxXXfzPO1N/SqR43Z8aXqXAAAAZAAIj6YAAAACAAAAAAAAAAEAAAAB0QAAAAAAAAEAAAAAAAAAAQAAAADLa6390PDAqg3qDLpshQxS+uVw3ytSgKRirQcInPWt1QAAAAAAAAAAA1Z+AAAAAAAAAAABfGl6lwAAAEBC655+8Izq54MIZrXTVF/E1ycHgQWpVcBD+LFkuOjjJd995u/7wM8sFqQqambL0/ME2FTOtxMO65B9i3eAIu4P";
    const TX_V1: &str = "AAAAAgAAAAAg4dbAxsGAGICfBG3iT2cKGYQ6hK4sJWzZ6or1C5v6GAAAAGQAJsOiAAAADQAAAAEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEAAAAAAAAACgAAAAVIZWxsbwAAAAAAAAEAAAAMU29yb2JhbiBEb2NzAAAAAAAAAAELm/oYAAAAQATr6Ghp/DNO7S6JjEFwcJ9a+dvI6NJr7I/2eQttvoovjQ8te4zKKaapC3mbmx6ld6YKL5T81mxs45TjzdG5zw0=";

    fn fee_bump_b64() -> (String, Transaction) {
        let (inner, _) = signed_inner(100, 1);
        let fee_kp = fee_keypair();
        let mut fb = FeeBumpTransaction::new(&fee_kp.public_key(), 100, &inner).unwrap();
        fb.sign(&[fee_kp]).unwrap();
        (fb.to_xdr_base64(), inner)
    }

    #[test]
    fn parses_tx_v0_envelope() {
        let tx = Transaction::from_xdr_envelope(TX_V0, Networks::public());
        assert_eq!(tx.envelope_type, xdr::EnvelopeType::TxV0);
        // A parsed TxV0 re-encodes to the same bytes.
        assert_eq!(
            tx.to_envelope()
                .unwrap()
                .to_xdr_base64(Limits::none())
                .unwrap(),
            TX_V0
        );
        let generic = GenericTransaction::from_xdr_envelope(TX_V0, Networks::public()).unwrap();
        assert_eq!(generic.as_transaction().unwrap().hash(), tx.hash());
        assert!(
            FeeBumpTransaction::from_xdr_envelope(TX_V0, Networks::public())
                == Err(FeeBumpError::NotFeeBump(xdr::EnvelopeType::TxV0))
        );
    }

    #[test]
    fn parses_tx_v1_envelope() {
        let tx = Transaction::from_xdr_envelope(TX_V1, Networks::testnet());
        assert_eq!(tx.envelope_type, xdr::EnvelopeType::Tx);
        let generic = GenericTransaction::from_xdr_envelope(TX_V1, Networks::testnet()).unwrap();
        assert!(generic.as_fee_bump().is_none());
        assert_eq!(generic.hash(), tx.hash());
        assert_eq!(
            generic
                .to_envelope()
                .unwrap()
                .to_xdr_base64(Limits::none())
                .unwrap(),
            TX_V1
        );
    }

    #[test]
    fn parses_fee_bump_envelope() {
        let (b64, inner) = fee_bump_b64();
        // Used to panic; now yields the inner transaction.
        let tx = Transaction::from_xdr_envelope(&b64, Networks::testnet());
        assert_eq!(tx.hash(), inner.hash());

        let generic = GenericTransaction::from_xdr_envelope(&b64, Networks::testnet()).unwrap();
        let fb = generic.as_fee_bump().expect("fee bump");
        assert_eq!(fb.inner_transaction_hash(), inner.hash());
        assert_eq!(generic.hash(), fb.hash());
        assert_eq!(
            generic
                .to_envelope()
                .unwrap()
                .to_xdr_base64(Limits::none())
                .unwrap(),
            b64
        );

        let via_builder = TransactionBuilder::from_xdr(&b64, Networks::testnet()).unwrap();
        assert_eq!(via_builder.hash(), fb.hash());
    }

    #[test]
    fn generic_parse_returns_error_on_invalid_xdr() {
        assert!(matches!(
            GenericTransaction::from_xdr_envelope("not base64 xdr", Networks::testnet()),
            Err(FeeBumpError::InvalidXdr(_))
        ));
    }
}
