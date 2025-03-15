use crate::hashing::HashingBehavior;
use crate::utils::decode_encode_muxed_account::encode_muxed_account_to_address;
use hex_literal::hex;
use num_bigint::BigUint;
use std::collections::hash_map::ValuesMut;
use std::error::Error;
use std::fmt;
use std::str::FromStr;
use stellar_strkey::ed25519::PublicKey;
use xdr::DecoratedSignature;
use xdr::Limits;
use xdr::SorobanTransactionData;

use crate::account::Account;
use crate::hashing::Sha256Hasher;
use crate::keypair::Keypair;
use crate::keypair::KeypairBehavior;
use crate::xdr;
use crate::xdr::ReadXdr;
use crate::xdr::WriteXdr;

#[derive(Debug, Clone)]
pub struct Transaction {
    pub tx: Option<xdr::Transaction>,
    pub tx_v0: Option<xdr::TransactionV0>,
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
    pub min_account_sequence_age: Option<u32>,
    pub min_account_sequence_ledger_gap: Option<u32>,
    pub extra_signers: Option<Vec<xdr::AccountId>>,
    pub operations: Option<Vec<xdr::Operation>>,
    pub hash: Option<[u8; 32]>,
    pub soroban_data: Option<SorobanTransactionData>,
}

// Define a trait for Transaction behavior
pub trait TransactionBehavior {
    fn signature_base(&self) -> Vec<u8>;
    fn hash(&self) -> [u8; 32];
    fn sign(&mut self, keypairs: &[Keypair]);
    fn to_envelope(&self) -> Result<xdr::TransactionEnvelope, Box<dyn Error>>;
    fn from_xdr_envelope(xdr: &str, network: &str) -> Self;
    //TODO: XDR Conversion, Proper From and To
}

impl TransactionBehavior for Transaction {
    fn signature_base(&self) -> Vec<u8> {
        let tagged_tx = if let Some(tx_v0) = &self.tx_v0 {
            // For V0 transactions, we need to reconstruct a Transaction from the V0 format
            // Similar to JS: "Backwards Compatibility: Use ENVELOPE_TYPE_TX to sign ENVELOPE_TYPE_TX_V0"
            xdr::TransactionSignaturePayloadTaggedTransaction::Tx(xdr::Transaction {
                source_account: xdr::MuxedAccount::Ed25519(tx_v0.source_account_ed25519.clone()),
                fee: tx_v0.fee,
                seq_num: tx_v0.seq_num.clone(),
                cond: match &tx_v0.time_bounds {
                    None => xdr::Preconditions::None,
                    Some(time_bounds) => xdr::Preconditions::Time(time_bounds.clone()),
                },
                memo: tx_v0.memo.clone(),
                operations: tx_v0.operations.clone(),
                ext: xdr::TransactionExt::V0,
            })
        } else if let Some(tx) = &self.tx {
            xdr::TransactionSignaturePayloadTaggedTransaction::Tx(tx.clone())
        } else {
            panic!("Transaction must have either tx or tx_v0 set")
        };

        let tx_sig = xdr::TransactionSignaturePayload {
            network_id: xdr::Hash(Sha256Hasher::hash(self.network_passphrase.as_bytes())),
            tagged_transaction: tagged_tx,
        };

        tx_sig.to_xdr(Limits::none()).unwrap()
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
        let raw_tx = self
            .tx
            .clone()
            .unwrap()
            .to_xdr_base64(xdr::Limits::none())
            .unwrap();

        let mut signatures =
            xdr::VecM::<DecoratedSignature, 20>::try_from(self.signatures.clone()).unwrap(); // Make a copy of the signatures

        let envelope = match self.envelope_type {
            xdr::EnvelopeType::TxV0 => {
                let transaction_v0 = xdr::TransactionV0Envelope {
                    tx: xdr::TransactionV0::from_xdr_base64(&raw_tx, xdr::Limits::none()).unwrap(), // Make a copy of tx
                    signatures,
                };
                xdr::TransactionEnvelope::TxV0(transaction_v0)
            }

            xdr::EnvelopeType::Tx => {
                let transaction_v1 = xdr::TransactionV1Envelope {
                    tx: xdr::Transaction::from_xdr_base64(&raw_tx, xdr::Limits::none()).unwrap(), // Make a copy of tx
                    signatures,
                };
                xdr::TransactionEnvelope::Tx(transaction_v1)
            }
            _ => {
                return Err(format!(
                    "Invalid TransactionEnvelope: expected an envelopeTypeTxV0 or envelopeTypeTx but received an {:?}.",
                    self.envelope_type
                )
                .into());
            }
        };

        Ok(envelope)
    }

    fn from_xdr_envelope(xdr: &str, network: &str) -> Self {
        let tx_env = xdr::TransactionEnvelope::from_xdr_base64(xdr, Limits::none()).unwrap();
        let envelope_type = tx_env.discriminant();

        match tx_env {
            xdr::TransactionEnvelope::TxV0(tx_v0_env) => Self {
                tx: None,
                tx_v0: Some(tx_v0_env.tx.clone()),
                network_passphrase: network.to_owned(),
                signatures: tx_v0_env.signatures.to_vec(),
                fee: tx_v0_env.tx.fee,
                envelope_type,
                memo: Some(tx_v0_env.tx.memo),
                sequence: Some(tx_v0_env.tx.seq_num.to_xdr_base64(Limits::none()).unwrap()),
                source: Some(
                    stellar_strkey::Strkey::PublicKeyEd25519(PublicKey(
                        tx_v0_env.tx.source_account_ed25519.0,
                    ))
                    .to_string(),
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
            },
            xdr::TransactionEnvelope::Tx(tx_env) => {
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
                        min_account_sequence = v2
                            .min_seq_num
                            .map(|seq| seq.to_xdr_base64(Limits::none()).unwrap());
                        min_account_sequence_age = Some(v2.min_seq_age);
                        min_account_sequence_ledger_gap = Some(v2.min_seq_ledger_gap);
                        extra_signers = Some(v2.extra_signers.to_vec());
                    }
                    xdr::Preconditions::None => {}
                }

                Self {
                    tx: Some(tx_env.clone().tx),
                    tx_v0: None,
                    network_passphrase: network.to_owned(),
                    signatures: tx_env.signatures.to_vec(),
                    fee: tx_env.tx.fee,
                    envelope_type,
                    memo: Some(tx_env.tx.memo),
                    sequence: Some(tx_env.tx.seq_num.to_xdr_base64(Limits::none()).unwrap()),
                    source: Some(encode_muxed_account_to_address(&tx_env.tx.source_account)),
                    time_bounds,
                    ledger_bounds,
                    min_account_sequence,
                    min_account_sequence_age: None,
                    min_account_sequence_ledger_gap,
                    extra_signers: None,
                    operations: Some(tx_env.tx.operations.to_vec()),
                    hash: None,
                    soroban_data: None,
                }
            }
            _ => panic!("Invalid envelope type"),
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

    #[test]
    fn constructs_transaction_object_from_transaction_envelope() {
        let source = Rc::new(RefCell::new(
            Account::new(
                "GBBM6BKZPEHWYO3E3YKREDPQXMS4VK35YLNU7NFBRI26RAN7GI5POFBB",
                "20",
            )
            .unwrap(),
        ));

        let destination = "GAAOFCNYV2OQUMVONXH2DOOQNNLJO7WRQ7E4INEZ7VH7JNG7IKBQAK5D";
        let asset = Asset::native();
        let amount = 2000 * operation::ONE;

        let mut builder = TransactionBuilder::new(source.clone(), Networks::testnet(), None)
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
        let mut tx = TransactionBuilder::new(source, Networks::testnet(), None)
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
        assert_eq!(verified, true);
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
        let tx = Transaction::from_xdr_envelope(xdr, Networks::public());

        println!("Transaction {}", tx);
        assert_eq!(
            hex::encode(tx.hash()),
            "a84d534b3742ad89413bdbf259e02fa4c5d039123769e9bcc63616f723a2bcd5"
        );
    }
}
