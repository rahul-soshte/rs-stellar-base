use crate::hashing::HashingBehavior;
use crate::utils::decode_encode_muxed_account::encode_muxed_account_to_address;
use std::collections::hash_map::ValuesMut;
use std::error::Error;
use std::fmt;
use std::str::FromStr;
use stellar_strkey::ed25519::PublicKey;
use xdr::DecoratedSignature;
use xdr::LedgerKey;
use xdr::Limits;
use xdr::SorobanTransactionData;

use crate::account::Account;
use crate::fee_bump_transaction::FeeBumpTransaction;
use crate::hashing::Sha256Hasher;
use crate::keypair::Keypair;
use crate::keypair::KeypairBehavior;
use crate::xdr;
use crate::xdr::ReadXdr;
use crate::xdr::WriteXdr;

/// A decoded transaction envelope of any supported transaction type.
#[derive(Debug, Clone)]
pub enum ParsedTransaction {
    /// An ordinary V0 or V1 transaction.
    Transaction(Transaction),
    /// A fee-bump transaction containing a signed V1 transaction.
    FeeBump(FeeBumpTransaction),
}

/// Errors decoding or selecting a transaction envelope.
#[derive(Debug)]
pub enum TransactionError {
    /// Invalid base64 or transaction envelope XDR.
    InvalidEnvelope(xdr::Error),
    /// An ordinary transaction was requested from a fee-bump envelope.
    UnexpectedFeeBump,
    /// A mutable transaction field cannot be represented in the selected format.
    InvalidField {
        /// Invalid or missing field.
        field: &'static str,
        /// Why the field cannot be converted.
        reason: &'static str,
    },
    /// Ordinary transactions can only use the V0 and V1 envelope types.
    UnsupportedEnvelopeType(xdr::EnvelopeType),
    /// A field exceeds its XDR bounds or cannot be encoded.
    Encoding(xdr::Error),
}

impl fmt::Display for TransactionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEnvelope(error) => write!(f, "invalid transaction envelope: {error}"),
            Self::UnexpectedFeeBump => {
                write!(f, "expected an ordinary transaction, found a fee bump")
            }
            Self::InvalidField { field, reason } => {
                write!(f, "invalid transaction {field}: {reason}")
            }
            Self::UnsupportedEnvelopeType(kind) => {
                write!(f, "unsupported ordinary transaction envelope: {kind:?}")
            }
            Self::Encoding(error) => write!(f, "transaction encoding error: {error}"),
        }
    }
}

impl Error for TransactionError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::InvalidEnvelope(error) => Some(error),
            Self::Encoding(error) => Some(error),
            _ => None,
        }
    }
}

impl ParsedTransaction {
    /// Recover the original envelope, including signatures and its envelope variant.
    pub fn to_envelope(&self) -> Result<xdr::TransactionEnvelope, TransactionError> {
        match self {
            Self::Transaction(transaction) => transaction.try_to_envelope(),
            Self::FeeBump(transaction) => Ok(transaction.to_envelope()),
        }
    }

    /// Select an ordinary transaction, refusing to silently unwrap a fee bump.
    pub fn into_transaction(self) -> Result<Transaction, TransactionError> {
        match self {
            Self::Transaction(transaction) => Ok(transaction),
            Self::FeeBump(_) => Err(TransactionError::UnexpectedFeeBump),
        }
    }
}

#[derive(Debug, Clone)]
pub struct Transaction {
    //pub tx: Option<xdr::Transaction>,
    //pub tx_v0: Option<xdr::TransactionV0>,
    pub network_passphrase: String,
    pub signatures: Vec<DecoratedSignature>,
    pub fee: u32,
    pub envelope_type: xdr::EnvelopeType,
    pub memo: Option<xdr::Memo>,
    pub sequence: Option<String>,
    pub source: Option<String>,
    pub time_bounds: Option<xdr::TimeBounds>,
    pub ledger_bounds: Option<xdr::LedgerBounds>,
    pub min_account_sequence: Option<String>,
    pub min_account_sequence_age: Option<u64>,
    pub min_account_sequence_ledger_gap: Option<u32>,
    pub extra_signers: Option<Vec<xdr::SignerKey>>,
    pub operations: Option<Vec<xdr::Operation>>,
    pub hash: Option<[u8; 32]>,
    pub soroban_data: Option<SorobanTransactionData>,
}

// Define a trait for Transaction behavior
pub trait TransactionBehavior {
    /// Build the signing payload. Panics on invalid mutable fields; use
    /// [`Transaction::try_signature_base`] for a fallible alternative.
    fn signature_base(&self) -> Vec<u8>;
    /// Compute the signing hash. Panics on invalid mutable fields; use
    /// [`Transaction::try_hash`] for a fallible alternative.
    fn hash(&self) -> [u8; 32];
    fn sign(&mut self, keypairs: &[Keypair]);
    fn to_envelope(&self) -> Result<xdr::TransactionEnvelope, Box<dyn Error>>;
    /// Decode any transaction envelope without panicking on untrusted input.
    fn from_xdr_envelope(xdr: &str, network: &str) -> Result<ParsedTransaction, TransactionError>;
    //TODO: XDR Conversion, Proper From and To
}

#[cfg(test)]
mod roundtrip_tests;

impl Transaction {
    fn to_tx(&self) -> Result<xdr::Transaction, TransactionError> {
        if !matches!(
            self.envelope_type,
            xdr::EnvelopeType::Tx | xdr::EnvelopeType::TxV0
        ) {
            return Err(TransactionError::UnsupportedEnvelopeType(
                self.envelope_type,
            ));
        }
        let invalid = |field, reason| TransactionError::InvalidField { field, reason };
        let source = self
            .source
            .as_deref()
            .ok_or_else(|| invalid("source", "missing account"))?;
        let source_account = xdr::MuxedAccount::from_str(source)
            .map_err(|_| invalid("source", "expected a G-address or M-address"))?;
        let sequence = self
            .sequence
            .as_deref()
            .ok_or_else(|| invalid("sequence", "missing sequence number"))?;
        let seq_num = xdr::SequenceNumber(
            sequence
                .parse()
                .map_err(|_| invalid("sequence", "expected an i64 decimal string"))?,
        );

        // Presence matters: even an all-zero V2 must keep its discriminant.
        // The parser marks V2 with Some(age/gap/signers), including their defaults.
        let has_v2 = self.ledger_bounds.is_some()
            || self.min_account_sequence.is_some()
            || self.min_account_sequence_age.is_some()
            || self.min_account_sequence_ledger_gap.is_some()
            || self.extra_signers.is_some();
        if self.envelope_type == xdr::EnvelopeType::TxV0 {
            if !matches!(source_account, xdr::MuxedAccount::Ed25519(_)) {
                return Err(invalid("source", "V0 does not support muxed accounts"));
            }
            if has_v2 {
                return Err(invalid(
                    "preconditions",
                    "V0 does not support V2 preconditions",
                ));
            }
            if self.soroban_data.is_some() {
                return Err(invalid("soroban_data", "V0 does not support Soroban data"));
            }
        }
        let cond = if has_v2 {
            xdr::Preconditions::V2(xdr::PreconditionsV2 {
                time_bounds: self.time_bounds.clone(),
                ledger_bounds: self.ledger_bounds.clone(),
                min_seq_num: self
                    .min_account_sequence
                    .as_deref()
                    .map(|seq| {
                        seq.parse().map(xdr::SequenceNumber).map_err(|_| {
                            invalid("min_account_sequence", "expected an i64 decimal string")
                        })
                    })
                    .transpose()?,
                min_seq_age: xdr::Duration(self.min_account_sequence_age.unwrap_or(0)),
                min_seq_ledger_gap: self.min_account_sequence_ledger_gap.unwrap_or(0),
                extra_signers: self
                    .extra_signers
                    .clone()
                    .unwrap_or_default()
                    .try_into()
                    .map_err(TransactionError::Encoding)?,
            })
        } else {
            self.time_bounds
                .clone()
                .map_or(xdr::Preconditions::None, xdr::Preconditions::Time)
        };
        Ok(xdr::Transaction {
            source_account,
            fee: self.fee,
            seq_num,
            cond,
            memo: self.memo.clone().unwrap_or(xdr::Memo::None),
            operations: self
                .operations
                .clone()
                .unwrap_or_default()
                .try_into()
                .map_err(TransactionError::Encoding)?,
            ext: self
                .soroban_data
                .clone()
                .map_or(xdr::TransactionExt::V0, xdr::TransactionExt::V1),
        })
    }

    /// Convert to an envelope with typed errors, never silently dropping fields.
    pub fn try_to_envelope(&self) -> Result<xdr::TransactionEnvelope, TransactionError> {
        let tx = self.to_tx()?;
        let signatures = self
            .signatures
            .clone()
            .try_into()
            .map_err(TransactionError::Encoding)?;
        if self.envelope_type == xdr::EnvelopeType::TxV0 {
            let xdr::MuxedAccount::Ed25519(source_account_ed25519) = tx.source_account else {
                return Err(TransactionError::InvalidField {
                    field: "source",
                    reason: "V0 does not support muxed accounts",
                });
            };
            Ok(xdr::TransactionEnvelope::TxV0(xdr::TransactionV0Envelope {
                tx: xdr::TransactionV0 {
                    source_account_ed25519,
                    fee: tx.fee,
                    seq_num: tx.seq_num,
                    time_bounds: self.time_bounds.clone(),
                    memo: tx.memo,
                    operations: tx.operations,
                    ext: xdr::TransactionV0Ext::V0,
                },
                signatures,
            }))
        } else {
            Ok(xdr::TransactionEnvelope::Tx(xdr::TransactionV1Envelope {
                tx,
                signatures,
            }))
        }
    }

    /// Build the signing payload with typed errors for invalid mutable fields.
    pub fn try_signature_base(&self) -> Result<Vec<u8>, TransactionError> {
        xdr::TransactionSignaturePayload {
            network_id: xdr::Hash(Sha256Hasher::hash(self.network_passphrase.as_bytes())),
            tagged_transaction: xdr::TransactionSignaturePayloadTaggedTransaction::Tx(
                self.to_tx()?,
            ),
        }
        .to_xdr(Limits::none())
        .map_err(TransactionError::Encoding)
    }

    /// Compute the signing hash with typed errors for invalid mutable fields.
    pub fn try_hash(&self) -> Result<[u8; 32], TransactionError> {
        Ok(Sha256Hasher::hash(self.try_signature_base()?))
    }
}

impl TransactionBehavior for Transaction {
    fn signature_base(&self) -> Vec<u8> {
        self.try_signature_base()
            .expect("invalid transaction; use try_signature_base for fallible conversion")
    }

    fn hash(&self) -> [u8; 32] {
        Sha256Hasher::hash(self.signature_base())
    }

    fn sign(&mut self, keypairs: &[Keypair]) {
        let tx_hash: [u8; 32] = self.hash();
        for kp in keypairs {
            let sig = kp.sign_decorated(&tx_hash);
            self.signatures.push(sig);
        }

        self.hash = Some(tx_hash);
    }

    fn to_envelope(&self) -> Result<xdr::TransactionEnvelope, Box<dyn Error>> {
        self.try_to_envelope()
            .map_err(|error| Box::new(error) as Box<dyn Error>)
    }

    fn from_xdr_envelope(xdr: &str, network: &str) -> Result<ParsedTransaction, TransactionError> {
        let tx_env = xdr::TransactionEnvelope::from_xdr_base64(xdr, Limits::none())
            .map_err(TransactionError::InvalidEnvelope)?;
        let envelope_type = tx_env.discriminant();

        Ok(match tx_env {
            xdr::TransactionEnvelope::TxV0(tx_v0_env) => ParsedTransaction::Transaction(Self {
                //tx: None,
                //tx_v0: Some(tx_v0_env.tx.clone()),
                network_passphrase: network.to_owned(),
                signatures: tx_v0_env.signatures.to_vec(),
                fee: tx_v0_env.tx.fee,
                envelope_type,
                memo: Some(tx_v0_env.tx.memo),
                sequence: Some(tx_v0_env.tx.seq_num.0.to_string()),
                source: Some(
                    stellar_strkey::Strkey::PublicKeyEd25519(PublicKey(
                        tx_v0_env.tx.source_account_ed25519.0,
                    ))
                    .to_string()
                    .as_str()
                    .to_owned(),
                ),
                time_bounds: tx_v0_env.tx.time_bounds,
                ledger_bounds: None,
                min_account_sequence: None,
                min_account_sequence_age: None,
                min_account_sequence_ledger_gap: None,
                extra_signers: None,
                operations: Some(tx_v0_env.tx.operations.to_vec()),
                hash: None,
                soroban_data: None,
            }),
            xdr::TransactionEnvelope::Tx(tx_env) => {
                ParsedTransaction::Transaction(Self::from_v1_envelope(tx_env, network))
            }
            xdr::TransactionEnvelope::TxFeeBump(envelope) => {
                ParsedTransaction::FeeBump(FeeBumpTransaction {
                    envelope,
                    network_passphrase: network.to_owned(),
                })
            }
        })
    }
}

impl Transaction {
    pub(crate) fn from_v1_envelope(tx_env: xdr::TransactionV1Envelope, network: &str) -> Self {
        let mut time_bounds = None;
        let mut ledger_bounds = None;
        let mut min_account_sequence = None;
        let mut min_account_sequence_age = None;
        let mut min_account_sequence_ledger_gap = None;
        let mut extra_signers = None;

        match tx_env.tx.cond.clone() {
            xdr::Preconditions::Time(tb) => {
                time_bounds = Some(tb);
            }
            xdr::Preconditions::V2(v2) => {
                time_bounds = v2.time_bounds;
                ledger_bounds = v2.ledger_bounds;
                min_account_sequence = v2.min_seq_num.map(|seq| seq.0.to_string());
                min_account_sequence_age = Some(v2.min_seq_age.0);
                min_account_sequence_ledger_gap = Some(v2.min_seq_ledger_gap);
                extra_signers = Some(v2.extra_signers.to_vec());
            }
            xdr::Preconditions::None => {}
        }

        Self {
            //tx: Some(tx_env.clone().tx),
            //tx_v0: None,
            network_passphrase: network.to_owned(),
            signatures: tx_env.signatures.to_vec(),
            fee: tx_env.tx.fee,
            envelope_type: xdr::EnvelopeType::Tx,
            memo: Some(tx_env.tx.memo),
            sequence: Some(tx_env.tx.seq_num.0.to_string()),
            source: Some(encode_muxed_account_to_address(&tx_env.tx.source_account)),
            time_bounds,
            ledger_bounds,
            min_account_sequence,
            min_account_sequence_age,
            min_account_sequence_ledger_gap,
            extra_signers,
            operations: Some(tx_env.tx.operations.to_vec()),
            hash: None,
            soroban_data: match tx_env.tx.ext {
                xdr::TransactionExt::V0 => None,
                xdr::TransactionExt::V1(data) => Some(data),
            },
        }
    }
}

impl fmt::Display for Transaction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Transaction {{")?;

        // Network information
        writeln!(f, "  Network: {}", self.network_passphrase)?;

        // Source account
        if let Some(source) = &self.source {
            writeln!(f, "  Source Account: {}", source)?;
        }

        // Fee
        writeln!(f, "  Fee: {}", self.fee)?;

        // Sequence number
        if let Some(sequence) = &self.sequence {
            writeln!(f, "  Sequence Number: {}", sequence)?;
        }

        // Memo
        if let Some(memo) = &self.memo {
            write!(f, "  Memo: ")?;
            match memo {
                xdr::Memo::Text(text) => writeln!(f, "TEXT: {:?}", text)?,
                xdr::Memo::Id(id) => writeln!(f, "ID: {}", id)?,
                xdr::Memo::Hash(hash) => writeln!(f, "HASH: {:?}", hash)?,
                xdr::Memo::Return(ret) => writeln!(f, "RETURN: {:?}", ret)?,
                xdr::Memo::None => writeln!(f, "NONE")?,
            }
        }

        // Time bounds
        if let Some(time_bounds) = &self.time_bounds {
            writeln!(f, "  Time Bounds: {{")?;
            writeln!(f, "    Min Time: {:?}", time_bounds.min_time)?;
            writeln!(f, "    Max Time: {:?}", time_bounds.max_time)?;
            writeln!(f, "  }}")?;
        }

        // Ledger bounds
        if let Some(ledger_bounds) = &self.ledger_bounds {
            writeln!(f, "  Ledger Bounds: {{")?;
            writeln!(f, "    Min Ledger: {}", ledger_bounds.min_ledger)?;
            writeln!(f, "    Max Ledger: {}", ledger_bounds.max_ledger)?;
            writeln!(f, "  }}")?;
        }

        // Min account sequence
        if let Some(min_seq) = &self.min_account_sequence {
            writeln!(f, "  Min Account Sequence: {}", min_seq)?;
        }

        // Min account sequence age
        if let Some(age) = &self.min_account_sequence_age {
            writeln!(f, "  Min Account Sequence Age: {}", age)?;
        }

        // Min account sequence ledger gap
        if let Some(gap) = &self.min_account_sequence_ledger_gap {
            writeln!(f, "  Min Account Sequence Ledger Gap: {}", gap)?;
        }

        // Operations
        if let Some(operations) = &self.operations {
            writeln!(f, "  Operations: [")?;
            for (i, op) in operations.iter().enumerate() {
                writeln!(f, "    {}. {:?}", i + 1, op)?;
            }
            writeln!(f, "  ]")?;
        }

        // Signatures
        writeln!(f, "  Signatures: [")?;
        for (i, sig) in self.signatures.iter().enumerate() {
            writeln!(
                f,
                "    {}. Hint: {:?}, Signature: {:?}",
                i + 1,
                sig.hint,
                sig.signature
            )?;
        }
        writeln!(f, "  ]")?;

        // Transaction hash
        if let Some(hash) = &self.hash {
            writeln!(f, "  Hash: {:?}", hash)?;
        }

        // Soroban data
        if let Some(soroban_data) = &self.soroban_data {
            writeln!(f, "  Soroban Data: {:?}", soroban_data)?;
        }

        write!(f, "}}")
    }
}

#[cfg(test)]
mod tests {

    use core::panic;
    use keypair::KeypairBehavior;
    use std::{cell::RefCell, rc::Rc};

    use sha2::digest::crypto_common::Key;
    use xdr::Limits;

    use super::*;
    use crate::{
        account::{Account, AccountBehavior},
        asset::{Asset, AssetBehavior},
        keypair::{self, Keypair},
        network::{NetworkPassphrase, Networks},
        operation::{self, Operation},
        transaction::TransactionBehavior,
        transaction_builder::{TransactionBuilder, TransactionBuilderBehavior, TIMEOUT_INFINITE},
    };

    fn parsing_fixture() -> xdr::TransactionV1Envelope {
        let mut source = Account::new(
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
            "20",
        )
        .unwrap();
        let tx = TransactionBuilder::new(&mut source, Networks::testnet(), None)
            .fee(100_u32)
            .add_operation(
                Operation::new()
                    .payment(
                        "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF",
                        &Asset::native(),
                        1,
                    )
                    .unwrap(),
            )
            .build();
        match tx.to_envelope().unwrap() {
            xdr::TransactionEnvelope::Tx(envelope) => envelope,
            _ => unreachable!(),
        }
    }

    fn parse_fixture(envelope: xdr::TransactionEnvelope) -> ParsedTransaction {
        Transaction::from_xdr_envelope(
            &envelope.to_xdr_base64(Limits::none()).unwrap(),
            Networks::testnet(),
        )
        .unwrap()
    }

    #[test]
    fn parses_v0_envelope() {
        let inner = parsing_fixture();
        let envelope = xdr::TransactionV0Envelope {
            tx: xdr::TransactionV0 {
                source_account_ed25519: xdr::Uint256([0; 32]),
                fee: inner.tx.fee,
                seq_num: inner.tx.seq_num,
                time_bounds: None,
                memo: inner.tx.memo,
                operations: inner.tx.operations,
                ext: xdr::TransactionV0Ext::V0,
            },
            signatures: inner.signatures,
        };
        let tx = parse_fixture(xdr::TransactionEnvelope::TxV0(envelope))
            .into_transaction()
            .unwrap();
        assert_eq!(tx.envelope_type, xdr::EnvelopeType::TxV0);
        assert_eq!(tx.sequence.as_deref(), Some("21"));
        assert_eq!(tx.fee, 100);
    }

    #[test]
    fn parses_v1_envelope_with_preconditions_and_soroban_data() {
        let mut inner = parsing_fixture();
        let signer = xdr::SignerKey::Ed25519(xdr::Uint256([7; 32]));
        inner.tx.cond = xdr::Preconditions::V2(xdr::PreconditionsV2 {
            time_bounds: None,
            ledger_bounds: None,
            min_seq_num: Some(xdr::SequenceNumber(12)),
            min_seq_age: xdr::Duration(u64::from(u32::MAX) + 34),
            min_seq_ledger_gap: 5,
            extra_signers: vec![signer.clone()].try_into().unwrap(),
        });
        let data = xdr::SorobanTransactionData::default();
        inner.tx.ext = xdr::TransactionExt::V1(data.clone());
        let tx = parse_fixture(xdr::TransactionEnvelope::Tx(inner))
            .into_transaction()
            .unwrap();
        assert_eq!(tx.envelope_type, xdr::EnvelopeType::Tx);
        assert_eq!(tx.min_account_sequence.as_deref(), Some("12"));
        assert_eq!(tx.min_account_sequence_age, Some(u64::from(u32::MAX) + 34));
        assert_eq!(tx.min_account_sequence_ledger_gap, Some(5));
        assert_eq!(tx.extra_signers, Some(vec![signer]));
        assert_eq!(tx.soroban_data, Some(data));
    }

    #[test]
    fn parses_fee_bump_and_recovers_signed_inner_transaction() {
        let mut inner = parsing_fixture();
        let signature = xdr::DecoratedSignature {
            hint: xdr::SignatureHint([1; 4]),
            signature: xdr::Signature(vec![2; 64].try_into().unwrap()),
        };
        inner.signatures = vec![signature.clone()].try_into().unwrap();
        let envelope = xdr::FeeBumpTransactionEnvelope {
            tx: xdr::FeeBumpTransaction {
                fee_source: xdr::MuxedAccount::Ed25519(xdr::Uint256([3; 32])),
                fee: i64::from(u32::MAX) + 1,
                inner_tx: xdr::FeeBumpTransactionInnerTx::Tx(inner.clone()),
                ext: xdr::FeeBumpTransactionExt::V0,
            },
            signatures: vec![signature].try_into().unwrap(),
        };
        let parsed = parse_fixture(xdr::TransactionEnvelope::TxFeeBump(envelope.clone()));
        assert!(matches!(
            parsed.clone().into_transaction(),
            Err(TransactionError::UnexpectedFeeBump)
        ));
        let ParsedTransaction::FeeBump(fee_bump) = parsed else {
            panic!("expected fee bump");
        };
        assert_eq!(fee_bump.envelope(), &envelope);
        assert_eq!(fee_bump.network_passphrase(), Networks::testnet());
        let recovered = fee_bump.inner_transaction();
        assert_eq!(recovered.signatures, inner.signatures.to_vec());
        assert_eq!(
            recovered.to_envelope().unwrap(),
            xdr::TransactionEnvelope::Tx(inner)
        );
    }

    #[test]
    fn rejects_invalid_envelopes_without_panicking() {
        for input in ["not base64!", "", "AAAAAg==", "AAAAAQ=="] {
            assert!(matches!(
                Transaction::from_xdr_envelope(input, Networks::testnet()),
                Err(TransactionError::InvalidEnvelope(_)),
            ));
        }
    }

    #[test]
    fn constructs_transaction_object_from_transaction_envelope() {
        let mut source = Account::new(
            "GBBM6BKZPEHWYO3E3YKREDPQXMS4VK35YLNU7NFBRI26RAN7GI5POFBB",
            "20",
        )
        .unwrap();

        let destination = "GAAOFCNYV2OQUMVONXH2DOOQNNLJO7WRQ7E4INEZ7VH7JNG7IKBQAK5D";
        let asset = Asset::native();
        let amount = 2000 * operation::ONE;

        let mut builder = TransactionBuilder::new(&mut source, Networks::testnet(), None)
            .fee(100_u32)
            .add_operation(
                Operation::new()
                    .payment(destination, &asset, amount)
                    .unwrap(),
            )
            .add_memo("Happy birthday!")
            .set_timeout(TIMEOUT_INFINITE)
            .unwrap()
            .build();

        //TODO: Tests still coming in for Envelope

        let destination = "GDJJRRMBK4IWLEPJGIE6SXD2LP7REGZODU7WDC3I2D6MR37F4XSHBKX2";
        let signer = Keypair::master(Some(Networks::testnet())).unwrap();
        let mut tx = TransactionBuilder::new(&mut source, Networks::testnet(), None)
            .fee(100_u32)
            .add_operation(
                Operation::new()
                    .create_account(destination, 10 * operation::ONE)
                    .unwrap(),
            )
            .build();

        tx.sign(&[signer.clone()]);
        let sig = &tx.signatures[0].signature.0;
        let verified = signer.verify(&tx.hash(), sig);
        assert!(verified);
    }

    #[test]
    fn can_successfully_decode_envelope() {
        // from https://github.com/stellar/js-stellar-sdk/issues/73
        let xdr = "AAAAAPQQv+uPYrlCDnjgPyPRgIjB6T8Zb8ANmL8YGAXC2IAgAAAAZAAIteYAAAAHAAAAAAAAAAAAAAABAAAAAAAAAAMAAAAAAAAAAUVVUgAAAAAAUtYuFczBLlsXyEp3q8BbTBpEGINWahqkFbnTPd93YUUAAAAXSHboAAAAABEAACcQAAAAAAAAAKIAAAAAAAAAAcLYgCAAAABAo2tU6n0Bb7bbbpaXacVeaTVbxNMBtnrrXVk2QAOje2Flllk/ORlmQdFU/9c8z43eWh1RNMpI3PscY+yDCnJPBQ==";

        // Decode base64 XDR
        let tx_env = xdr::TransactionEnvelope::from_xdr_base64(xdr, Limits::none()).unwrap();

        let tx = match tx_env {
            xdr::TransactionEnvelope::TxV0(transaction_v0_envelope) => transaction_v0_envelope.tx,
            _ => panic!("fff"),
        };

        let source_account = tx.source_account_ed25519;
        assert_eq!(source_account.0.len(), 32);
    }

    #[test]
    fn calculates_correct_hash_with_non_utf8_strings() {
        let xdr = "AAAAAAtjwtJadppTmm0NtAU99BFxXXfzPO1N/SqR43Z8aXqXAAAAZAAIj6YAAAACAAAAAAAAAAEAAAAB0QAAAAAAAAEAAAAAAAAAAQAAAADLa6390PDAqg3qDLpshQxS+uVw3ytSgKRirQcInPWt1QAAAAAAAAAAA1Z+AAAAAAAAAAABfGl6lwAAAEBC655+8Izq54MIZrXTVF/E1ycHgQWpVcBD+LFkuOjjJd995u/7wM8sFqQqambL0/ME2FTOtxMO65B9i3eAIu4P";
        let tx = Transaction::from_xdr_envelope(xdr, Networks::public())
            .unwrap()
            .into_transaction()
            .unwrap();

        println!("Transaction {}", tx);
        assert_eq!(
            hex::encode(tx.hash()),
            "a84d534b3742ad89413bdbf259e02fa4c5d039123769e9bcc63616f723a2bcd5"
        );
    }
}
