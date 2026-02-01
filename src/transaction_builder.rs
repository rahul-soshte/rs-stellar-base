use std::collections::hash_map::ValuesMut;
use std::error::Error;
use std::str::FromStr;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use serde_json::from_str;

use crate::account::Account;
use crate::account::AccountBehavior;
use crate::hashing::Sha256Hasher;
use crate::keypair::Keypair;
use crate::transaction::Transaction;
use crate::utils::decode_encode_muxed_account::decode_address_fully_to_muxed_account;
use crate::utils::decode_encode_muxed_account::decode_address_to_muxed_account;
use crate::utils::decode_encode_muxed_account::decode_address_to_muxed_account_fix_for_g_address;
use crate::utils::decode_encode_muxed_account::encode_muxed_account;
use crate::xdr;
use crate::xdr::ReadXdr;
use crate::xdr::WriteXdr;

#[derive(Default)]
pub struct TransactionBuilder<'a> {
    tx: Option<xdr::Transaction>,
    tx_v0: Option<xdr::TransactionV0>,
    network_passphrase: Option<String>,
    signatures: Option<Vec<xdr::DecoratedSignature>>,
    fee: Option<u32>,
    envelope_type: Option<xdr::EnvelopeType>,
    memo: Option<xdr::Memo>,
    sequence: Option<String>,
    source: Option<&'a mut Account>,
    time_bounds: Option<xdr::TimeBounds>,
    ledger_bounds: Option<xdr::LedgerBounds>,
    min_account_sequence: Option<String>,
    min_account_sequence_age: Option<u32>,
    min_account_sequence_ledger_gap: Option<u32>,
    extra_signers: Option<Vec<xdr::AccountId>>,
    operations: Option<Vec<xdr::Operation>>,
    soroban_data: Option<xdr::SorobanTransactionData>,
}

// Define a trait for TransactionBuilder behavior
pub trait TransactionBuilderBehavior<'a> {
    fn build_for_simulation(&self) -> Transaction;
    fn set_soroban_data_from_xdr_base64(&mut self, soroban_data: &str) -> &mut Self;
    fn new(
        source_account: &'a mut Account,
        network: &str,
        time_bounds: Option<xdr::TimeBounds>,
    ) -> Self;
    fn fee(&mut self, fee: impl Into<u32>) -> &mut Self;
    fn add_operation(&mut self, operation: xdr::Operation) -> &mut Self;
    fn build(&mut self) -> Transaction;
    fn add_memo(&mut self, memo_text: &str) -> &mut Self;
    fn set_timeout(&mut self, timeout_seconds: i64) -> Result<&mut Self, String>;
    fn set_time_bounds(&mut self, time_bounds: xdr::TimeBounds) -> &mut Self;
    fn set_ledger_bounds(&mut self, ledger_bounds: xdr::LedgerBounds) -> &mut Self;
    fn set_soroban_data(&mut self, soroban_data: xdr::SorobanTransactionData) -> &mut Self;
    fn clear_operations(&mut self) -> &mut Self;
}

pub const TIMEOUT_INFINITE: i64 = 0;

impl<'a> TransactionBuilderBehavior<'a> for TransactionBuilder<'a> {
    fn new(
        source_account: &'a mut Account,
        network: &str,
        time_bounds: Option<xdr::TimeBounds>,
    ) -> Self {
        Self {
            tx: None,
            tx_v0: None,
            network_passphrase: Some(network.to_string()),
            signatures: None,
            fee: None,
            envelope_type: None,
            memo: None,
            sequence: None,
            source: Some(source_account),
            time_bounds,
            ledger_bounds: None,
            min_account_sequence: None,
            min_account_sequence_age: None,
            min_account_sequence_ledger_gap: None,
            extra_signers: None,
            operations: Some(Vec::new()),
            soroban_data: None,
        }
    }

    fn fee(&mut self, fee: impl Into<u32>) -> &mut Self {
        self.fee.insert(fee.into());
        self
    }

    fn add_operation(&mut self, operation: xdr::Operation) -> &mut Self {
        if let Some(ref mut vec) = self.operations {
            vec.push(operation);
        }
        self
    }

    fn add_memo(&mut self, memo_text: &str) -> &mut Self {
        self.memo = Some(xdr::Memo::Text(
            xdr::StringM::<28>::from_str(memo_text).unwrap(),
        ));
        self
    }

    fn set_timeout(&mut self, timeout_seconds: i64) -> Result<&mut Self, String> {
        if let Some(timebounds) = &self.time_bounds {
            if timebounds.max_time > xdr::TimePoint(0) {
                return Err("TimeBounds.max_time has been already set - setting timeout would overwrite it.".to_string());
            }
        }

        if timeout_seconds < 0 {
            return Err("timeout cannot be negative".to_string());
        }

        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| format!("Error getting current time: {}", e))?
            .as_secs();

        if timeout_seconds > 0 {
            let timeout_timestamp = current_time + timeout_seconds as u64;
            self.time_bounds = Some(xdr::TimeBounds {
                min_time: self
                    .time_bounds
                    .as_ref()
                    .map_or(xdr::TimePoint(0), |tb| tb.min_time.clone()),
                max_time: xdr::TimePoint(timeout_timestamp),
            });
        } else {
            self.time_bounds = Some(xdr::TimeBounds {
                min_time: xdr::TimePoint(0),
                max_time: xdr::TimePoint(0),
            });
        }

        Ok(self)
    }

    fn set_time_bounds(&mut self, time_bounds: xdr::TimeBounds) -> &mut Self {
        self.time_bounds = Some(time_bounds);
        self
    }

    fn set_ledger_bounds(&mut self, ledger_bounds: xdr::LedgerBounds) -> &mut Self {
        self.ledger_bounds = Some(ledger_bounds);
        self
    }

    fn set_soroban_data(&mut self, soroban_data: xdr::SorobanTransactionData) -> &mut Self {
        self.soroban_data = Some(soroban_data);
        self
    }

    fn set_soroban_data_from_xdr_base64(&mut self, soroban_data: &str) -> &mut Self {
        let data = xdr::SorobanTransactionData::from_xdr_base64(soroban_data, xdr::Limits::none())
            .unwrap();
        self.soroban_data = Some(data);
        self
    }

    fn clear_operations(&mut self) -> &mut Self {
        self.operations = Some(Vec::new());
        self
    }

    fn build(&mut self) -> Transaction {
        let source = self.source.as_mut().expect("Source account not set");

        // Increment the sequence number directly on the mutable reference
        source.increment_sequence_number();

        let fee = self
            .fee
            .unwrap()
            .checked_mul(self.operations.clone().unwrap().len().try_into().unwrap());
        let account_id = source.account_id();
        let sequence_number = source.sequence_number();

        let ext_on_the_fly = if self.soroban_data.is_some() {
            xdr::TransactionExt::V1(self.soroban_data.clone().unwrap())
        } else {
            xdr::TransactionExt::V0
        };
        let vv = decode_address_to_muxed_account_fix_for_g_address(&account_id);

        let tx_cond = match (&self.time_bounds, &self.ledger_bounds) {
            (None, None) => xdr::Preconditions::None,
            (Some(tb), None) => xdr::Preconditions::Time(tb.clone()),
            (time_bounds, ledger_bounds) => xdr::Preconditions::V2(xdr::PreconditionsV2 {
                time_bounds: time_bounds.as_ref().cloned(),
                ledger_bounds: ledger_bounds.as_ref().cloned(),
                min_seq_num: None,
                min_seq_age: xdr::Duration(0),
                min_seq_ledger_gap: 0,
                extra_signers: xdr::VecM::default(),
            }),
        };
        let envelope_type = if self.soroban_data.is_some() {
            xdr::EnvelopeType::Tx
        } else {
            xdr::EnvelopeType::TxV0
        };

        let tx_obj = xdr::Transaction {
            source_account: vv,
            fee: fee.unwrap(),
            seq_num: xdr::SequenceNumber(
                sequence_number
                    .parse()
                    .unwrap_or_else(|_| panic!("Number too large for i64")),
            ),
            cond: tx_cond,
            memo: self.memo.clone().unwrap_or(xdr::Memo::None),
            operations: self.operations.clone().unwrap().try_into().unwrap(),
            ext: ext_on_the_fly,
        };
        Transaction {
            //tx: Some(tx_obj),
            network_passphrase: self.network_passphrase.clone().unwrap(),
            signatures: Vec::new(),
            fee: fee.unwrap(),
            envelope_type: xdr::EnvelopeType::Tx,
            memo: self.memo.clone(),
            sequence: Some(sequence_number),
            source: Some(account_id.to_string()),
            time_bounds: self.time_bounds.clone(),
            ledger_bounds: self.ledger_bounds.clone(),
            min_account_sequence: Some("0".to_string()),
            min_account_sequence_age: Some(0),
            min_account_sequence_ledger_gap: Some(0),
            extra_signers: Some(Vec::new()),
            operations: self.operations.clone(),
            hash: None,
            soroban_data: self.soroban_data.clone(),
            //tx_v0: None,
        }
    }

    /// # Build a transaction for simulation only
    ///
    /// This method builds a transaction without incrementing the source account's sequence number.
    /// It should be used when you only want to simulate a transaction and not actually submit it
    /// to the network.
    ///
    /// Unlike [`build()`](TransactionBuilderBehavior::build), this method:
    /// - Does NOT increment the source account's sequence number
    /// - Only requires an immutable reference to self (`&self` instead of `&mut self`)
    /// - Is safe to use for read-only operations like transaction simulation
    ///
    /// # When to use this method
    ///
    /// Use `build_for_simulation()` when:
    /// - You want to call [`Server::simulate_transaction`](crate::Server::simulate_transaction)
    /// - You're testing transaction logic without submitting to the network
    /// - You need to preview transaction fees or resource requirements
    /// - You want to build multiple "what-if" scenarios without affecting account state
    ///
    /// Use `build()` when:
    /// - You're building a transaction to actually submit to the network
    /// - You want the account's sequence number to be incremented
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// use stellar_baselib::*;
    /// use stellar_baselib::account::AccountBehavior;
    /// use stellar_baselib::network::NetworkPassphrase;
    /// use stellar_baselib::transaction_builder::{TransactionBuilder, TransactionBuilderBehavior};
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mut source_account = account::Account::new("GABC...", "100")?;
    /// # let network = network::Networks::testnet();
    ///
    /// // For simulation - doesn't mutate the account
    /// let mut builder = TransactionBuilder::new(&mut source_account, network, None);
    /// builder.fee(1000u32);
    /// // ... add operations ...
    /// let tx_for_simulation = builder.build_for_simulation();
    ///
    /// // source_account sequence number is unchanged
    /// // You can now simulate: rpc.simulate_transaction(&tx_for_simulation, None).await?;
    ///
    /// // For actual submission - increments the sequence number
    /// let tx_for_submission = builder.build();
    /// // source_account sequence number is now incremented
    /// # Ok(())
    /// # }
    /// ```
    fn build_for_simulation(&self) -> Transaction {
        let source = self.source.as_ref().expect("Source account not set");

        // Calculate the next sequence number (current + 1) without mutating the account
        let current_seq: i64 = source
            .sequence_number()
            .parse()
            .expect("Invalid sequence number");
        let next_sequence_number = (current_seq + 1).to_string();
        let account_id = source.account_id();

        let fee = self
            .fee
            .unwrap()
            .checked_mul(self.operations.clone().unwrap().len().try_into().unwrap());

        let ext_on_the_fly = if self.soroban_data.is_some() {
            xdr::TransactionExt::V1(self.soroban_data.clone().unwrap())
        } else {
            xdr::TransactionExt::V0
        };
        let vv = decode_address_to_muxed_account_fix_for_g_address(&account_id);

        let tx_cond = match (&self.time_bounds, &self.ledger_bounds) {
            (None, None) => xdr::Preconditions::None,
            (Some(tb), None) => xdr::Preconditions::Time(tb.clone()),
            (time_bounds, ledger_bounds) => xdr::Preconditions::V2(xdr::PreconditionsV2 {
                time_bounds: time_bounds.as_ref().cloned(),
                ledger_bounds: ledger_bounds.as_ref().cloned(),
                min_seq_num: None,
                min_seq_age: xdr::Duration(0),
                min_seq_ledger_gap: 0,
                extra_signers: xdr::VecM::default(),
            }),
        };
        let envelope_type = if self.soroban_data.is_some() {
            xdr::EnvelopeType::Tx
        } else {
            xdr::EnvelopeType::TxV0
        };

        let tx_obj = xdr::Transaction {
            source_account: vv,
            fee: fee.unwrap(),
            seq_num: xdr::SequenceNumber(
                next_sequence_number
                    .parse()
                    .unwrap_or_else(|_| panic!("Number too large for i64")),
            ),
            cond: tx_cond,
            memo: self.memo.clone().unwrap_or(xdr::Memo::None),
            operations: self.operations.clone().unwrap().try_into().unwrap(),
            ext: ext_on_the_fly,
        };
        Transaction {
            //tx: Some(tx_obj),
            network_passphrase: self.network_passphrase.clone().unwrap(),
            signatures: Vec::new(),
            fee: fee.unwrap(),
            envelope_type: xdr::EnvelopeType::Tx,
            memo: self.memo.clone(),
            sequence: Some(next_sequence_number),
            source: Some(account_id.to_string()),
            time_bounds: self.time_bounds.clone(),
            ledger_bounds: self.ledger_bounds.clone(),
            min_account_sequence: Some("0".to_string()),
            min_account_sequence_age: Some(0),
            min_account_sequence_ledger_gap: Some(0),
            extra_signers: Some(Vec::new()),
            operations: self.operations.clone(),
            hash: None,
            soroban_data: self.soroban_data.clone(),
            //tx_v0: None,
        }
    }
}

#[cfg(test)]
mod tests {

    use core::panic;
    use keypair::KeypairBehavior;

    use sha2::digest::crypto_common::Key;
    use xdr::ScAddress::Contract;
    use xdr::{Hash, HostFunction, InvokeContractArgs, ScAddress, ScString, ScSymbol, ScVal};

    use super::*;
    use crate::operation;
    // use crate::{
    //     account::Account, asset::{Asset, AssetBehavior}, keypair::{self, Keypair}, network::{NetworkPassphrase, Networks}, operation::PaymentOpts, transaction::TransactionBehavior
    // };
    use crate::{
        account::{Account, AccountBehavior},
        asset::{Asset, AssetBehavior},
        contract::{ContractBehavior, Contracts},
        keypair::{self, Keypair},
        network::{NetworkPassphrase, Networks},
        op_list::invoke_host,
        operation::Operation,
        soroban_data_builder::{SorobanDataBuilder, SorobanDataBuilderBehavior},
        transaction::{self, TransactionBehavior},
        transaction_builder::{TransactionBuilder, TransactionBuilderBehavior, TIMEOUT_INFINITE},
    };

    #[test]
    fn test_creates_and_signs() {
        let mut source = Account::new(
            "GBBM6BKZPEHWYO3E3YKREDPQXMS4VK35YLNU7NFBRI26RAN7GI5POFBB",
            "20",
        )
        .unwrap();

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
    fn test_constructs_native_payment_transaction() {
        let mut source = Account::new(
            "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ",
            "0",
        )
        .unwrap();

        let destination = "GDJJRRMBK4IWLEPJGIE6SXD2LP7REGZODU7WDC3I2D6MR37F4XSHBKX2";
        let amount = 1000 * operation::ONE;
        let asset = Asset::native();
        let memo = xdr::Memo::Id(100);
        let mut builder = TransactionBuilder::new(&mut source, Networks::testnet(), None);

        builder
            .fee(100_u32)
            .add_operation(
                Operation::new()
                    .payment(destination, &asset, amount)
                    .unwrap(),
            )
            .add_memo("100")
            .set_timeout(TIMEOUT_INFINITE)
            .unwrap();

        let transaction = builder.build();

        assert_eq!(transaction.source, Some(source.account_id().to_string()));
        assert_eq!(transaction.sequence.unwrap(), "1");
        assert_eq!(source.sequence_number(), "1");
        assert_eq!(transaction.operations.unwrap().len(), 1);
        assert_eq!(transaction.fee, 100);
    }

    #[test]
    fn test_constructs_native_payment_transaction_with_two_operations() {
        let mut source = Account::new(
            "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ",
            "0",
        )
        .unwrap();

        let destination1 = "GDJJRRMBK4IWLEPJGIE6SXD2LP7REGZODU7WDC3I2D6MR37F4XSHBKX2";
        let amount1 = 1000 * operation::ONE;
        let destination2 = "GC6ACGSA2NJGD6YWUNX2BYBL3VM4MZRSEU2RLIUZZL35NLV5IAHAX2E2";
        let amount2 = 2000 * operation::ONE;
        let asset = Asset::native();

        let mut builder = TransactionBuilder::new(&mut source, Networks::testnet(), None);

        builder
            .fee(100_u32)
            .add_operation(
                Operation::new()
                    .payment(destination1, &asset, amount1)
                    .unwrap(),
            )
            .add_operation(
                Operation::new()
                    .payment(destination2, &asset, amount2)
                    .unwrap(),
            )
            .set_timeout(TIMEOUT_INFINITE)
            .unwrap();

        let transaction = builder.build();

        assert_eq!(transaction.source, Some(source.account_id().to_string()));
        assert_eq!(transaction.sequence.unwrap(), "1");
        assert_eq!(source.sequence_number(), "1");
        assert_eq!(transaction.operations.unwrap().len(), 2);
        assert_eq!(transaction.fee, 200);
    }

    #[test]
    fn constructs_native_payment_transaction_with_custom_base_fee() {
        // Set up test data
        let mut source = Account::new(
            "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ",
            "0",
        )
        .unwrap();

        let destination1 = "GDJJRRMBK4IWLEPJGIE6SXD2LP7REGZODU7WDC3I2D6MR37F4XSHBKX2";
        let amount1 = 1000 * operation::ONE;
        let destination2 = "GC6ACGSA2NJGD6YWUNX2BYBL3VM4MZRSEU2RLIUZZL35NLV5IAHAX2E2";
        let amount2 = 2000 * operation::ONE;
        let asset = Asset::native();

        // Create transaction
        let mut builder = TransactionBuilder::new(&mut source, Networks::testnet(), None);
        let transaction = builder
            .fee(1000_u32) // Set custom base fee
            .add_operation(
                Operation::new()
                    .payment(destination1, &asset, amount1)
                    .unwrap(),
            )
            .add_operation(
                Operation::new()
                    .payment(destination2, &asset, amount2)
                    .unwrap(),
            )
            .set_timeout(TIMEOUT_INFINITE)
            .unwrap()
            .build();

        // Assert that the total fee is 2000 stroops (1000 per operation, 2 operations)
        assert_eq!(transaction.fee, 2000);
    }

    #[test]
    fn constructs_native_payment_transaction_with_integer_timebounds() {
        let mut source = Account::new(
            "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ",
            "0",
        )
        .unwrap();

        let timebounds = xdr::TimeBounds {
            min_time: xdr::TimePoint(1455287522),
            max_time: xdr::TimePoint(1455297545),
        };

        let mut builder =
            TransactionBuilder::new(&mut source, Networks::testnet(), Some(timebounds.clone()));
        builder.fee(100_u32).add_operation(
            Operation::new()
                .payment(
                    "GDJJRRMBK4IWLEPJGIE6SXD2LP7REGZODU7WDC3I2D6MR37F4XSHBKX2",
                    &Asset::native(),
                    1000 * operation::ONE,
                )
                .unwrap(),
        );

        // Set the timebounds
        builder.time_bounds = Some(timebounds.clone());

        let transaction = builder.build();

        assert_eq!(
            transaction.time_bounds.as_ref().unwrap().min_time,
            timebounds.min_time
        );
        assert_eq!(
            transaction.time_bounds.as_ref().unwrap().max_time,
            timebounds.max_time
        );
    }

    #[test]
    fn constructs_native_payment_transaction_with_ledger_bounds() {
        let mut source = Account::new(
            "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ",
            "0",
        )
        .unwrap();

        let ledger_bounds = xdr::LedgerBounds {
            min_ledger: 1000,
            max_ledger: 2000,
        };

        let mut builder = TransactionBuilder::new(&mut source, Networks::testnet(), None);
        builder
            .fee(100_u32)
            .add_operation(
                Operation::new()
                    .payment(
                        "GDJJRRMBK4IWLEPJGIE6SXD2LP7REGZODU7WDC3I2D6MR37F4XSHBKX2",
                        &Asset::native(),
                        1000 * operation::ONE,
                    )
                    .unwrap(),
            )
            .set_ledger_bounds(ledger_bounds.clone())
            .set_timeout(TIMEOUT_INFINITE)
            .unwrap();

        let transaction = builder.build();

        assert_eq!(
            transaction.ledger_bounds.as_ref().unwrap().min_ledger,
            ledger_bounds.min_ledger
        );
        assert_eq!(
            transaction.ledger_bounds.as_ref().unwrap().max_ledger,
            ledger_bounds.max_ledger
        );
    }

    #[test]
    fn constructs_native_payment_transaction_with_time_and_ledger_bounds() {
        let mut source = Account::new(
            "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ",
            "0",
        )
        .unwrap();

        let timebounds = xdr::TimeBounds {
            min_time: xdr::TimePoint(1455287522),
            max_time: xdr::TimePoint(1455297545),
        };

        let ledger_bounds = xdr::LedgerBounds {
            min_ledger: 1000,
            max_ledger: 2000,
        };

        let mut builder =
            TransactionBuilder::new(&mut source, Networks::testnet(), Some(timebounds.clone()));
        builder
            .fee(100_u32)
            .add_operation(
                Operation::new()
                    .payment(
                        "GDJJRRMBK4IWLEPJGIE6SXD2LP7REGZODU7WDC3I2D6MR37F4XSHBKX2",
                        &Asset::native(),
                        1000 * operation::ONE,
                    )
                    .unwrap(),
            )
            .set_ledger_bounds(ledger_bounds.clone());

        let transaction = builder.build();

        // Verify time bounds
        assert_eq!(
            transaction.time_bounds.as_ref().unwrap().min_time,
            timebounds.min_time
        );
        assert_eq!(
            transaction.time_bounds.as_ref().unwrap().max_time,
            timebounds.max_time
        );

        // Verify ledger bounds
        assert_eq!(
            transaction.ledger_bounds.as_ref().unwrap().min_ledger,
            ledger_bounds.min_ledger
        );
        assert_eq!(
            transaction.ledger_bounds.as_ref().unwrap().max_ledger,
            ledger_bounds.max_ledger
        );
    }

    //TODO: Compatibilty of TimeBounds with chrono date
    //TODO: Soroban Data Builder

    #[test]
    fn constructs_a_transaction_with_soroban_data() {
        // Arrange
        let mut source = Account::new(
            "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ",
            "0",
        )
        .unwrap();

        let mut soroban_data_builder = SorobanDataBuilder::new(None);
        soroban_data_builder
            .set_resources(0, 5, 0)
            .set_refundable_fee(1);
        let soroban_transaction_data = soroban_data_builder.build();

        let contract_id = "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE";
        let binding = hex::encode(contract_id);
        let hex_id = binding.as_bytes();
        let mut array = [0u8; 32];
        array.copy_from_slice(&hex_id[0..32]);

        let func = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: Contract(xdr::ContractId(Hash::from(array))),
            function_name: ScSymbol::from(xdr::StringM::from_str("hello").unwrap()),
            args: vec![ScVal::String(ScString::from(
                xdr::StringM::from_str("world").unwrap(),
            ))]
            .try_into()
            .unwrap(),
        });

        // Act
        let mut transaction_builder =
            TransactionBuilder::new(&mut source, Networks::testnet(), None);
        let transaction = transaction_builder
            .fee(100_u32)
            .add_operation(Operation::new().invoke_host_function(func, None).unwrap())
            .set_soroban_data(soroban_transaction_data.clone())
            .set_timeout(TIMEOUT_INFINITE)
            .unwrap()
            .build();

        // Assert
        assert_eq!(transaction.soroban_data, Some(soroban_transaction_data));
        assert_eq!(transaction.operations.unwrap().len(), 1);
        assert_eq!(transaction.fee, 100);
    }

    #[test]
    fn test_set_soroban_data_from_xdr() {
        // Arrange
        let mut source = Account::new(
            "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ",
            "0",
        )
        .unwrap();

        let contract_id = "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE";
        let binding = hex::encode(contract_id);
        let hex_id = binding.as_bytes();
        let mut array = [0u8; 32];
        array.copy_from_slice(&hex_id[0..32]);

        let func = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: Contract(xdr::ContractId(Hash::from(array))),
            function_name: ScSymbol::from(xdr::StringM::from_str("hello").unwrap()),
            args: vec![xdr::ScVal::String(ScString::from(
                xdr::StringM::from_str("world").unwrap(),
            ))]
            .try_into()
            .unwrap(),
        });

        let mut soroban_data_builder = SorobanDataBuilder::new(None);
        soroban_data_builder
            .set_resources(0, 5, 0)
            .set_refundable_fee(1);
        let soroban_transaction_data = soroban_data_builder.build();

        // Act
        let mut transaction_builder =
            TransactionBuilder::new(&mut source, Networks::testnet(), None);
        let transaction = transaction_builder
            .fee(100_u32)
            .add_operation(Operation::new().invoke_host_function(func, None).unwrap())
            .set_soroban_data_from_xdr_base64(
                &(soroban_transaction_data
                    .clone()
                    .to_xdr_base64(xdr::Limits::none())
                    .unwrap()),
            )
            .set_timeout(TIMEOUT_INFINITE)
            .unwrap()
            .build();

        // Assert
        assert_eq!(transaction.soroban_data, Some(soroban_transaction_data));
        assert_eq!(transaction.operations.unwrap().len(), 1);
        assert_eq!(transaction.fee, 100);
    }

    #[test]
    fn test_set_transaction_ext_when_soroban_data_present() {
        // Arrange
        let mut source = Account::new(
            "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ",
            "0",
        )
        .unwrap();

        let contract_id = "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE";
        let binding = hex::encode(contract_id);
        let hex_id = binding.as_bytes();
        let mut array = [0u8; 32];
        array.copy_from_slice(&hex_id[0..32]);

        let func = HostFunction::InvokeContract(InvokeContractArgs {
            contract_address: Contract(xdr::ContractId(Hash::from(array))),
            function_name: ScSymbol::from(xdr::StringM::from_str("hello").unwrap()),
            args: vec![ScVal::String(ScString::from(
                xdr::StringM::from_str("world").unwrap(),
            ))]
            .try_into()
            .unwrap(),
        });

        let mut soroban_data_builder = SorobanDataBuilder::new(None);
        soroban_data_builder
            .set_resources(0, 5, 0)
            .set_refundable_fee(1);
        let soroban_transaction_data = soroban_data_builder.build();

        // Act
        let mut transaction_builder =
            TransactionBuilder::new(&mut source, Networks::testnet(), None);
        let transaction = transaction_builder
            .fee(100_u32)
            .add_operation(Operation::new().invoke_host_function(func, None).unwrap())
            .set_soroban_data_from_xdr_base64(
                &(soroban_transaction_data
                    .clone()
                    .to_xdr_base64(xdr::Limits::none())
                    .unwrap()),
            )
            .set_timeout(TIMEOUT_INFINITE)
            .unwrap()
            .build();

        // Assert

        let tx_env = transaction.to_envelope().unwrap();

        let val = match tx_env {
            xdr::TransactionEnvelope::Tx(transaction_v1_envelope) => transaction_v1_envelope,
            _ => panic!("Wrong"),
        };

        let inner_val = val.tx.ext;
        assert_eq!(inner_val, xdr::TransactionExt::V1(soroban_transaction_data));
    }

    #[test]
    fn test_build_for_simulation_does_not_increment_sequence() {
        // Arrange
        let mut source = Account::new(
            "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ",
            "100",
        )
        .unwrap();

        let destination = "GDJJRRMBK4IWLEPJGIE6SXD2LP7REGZODU7WDC3I2D6MR37F4XSHBKX2";
        let asset = Asset::native();

        let mut builder = TransactionBuilder::new(&mut source, Networks::testnet(), None);
        builder
            .fee(100_u32)
            .add_operation(
                Operation::new()
                    .payment(destination, &asset, 1000 * operation::ONE)
                    .unwrap(),
            )
            .set_timeout(TIMEOUT_INFINITE)
            .unwrap();

        // Act - build for simulation
        let tx_for_simulation = builder.build_for_simulation();

        // Assert - transaction uses next sequence (101) but doesn't mutate the account
        assert_eq!(tx_for_simulation.sequence.unwrap(), "101");

        // Drop the builder to release the mutable borrow
        drop(builder);

        // Assert - sequence number should NOT be incremented (still 100)
        assert_eq!(source.sequence_number(), "100");
    }

    #[test]
    fn test_build_increments_sequence_number() {
        // Arrange
        let mut source = Account::new(
            "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ",
            "50",
        )
        .unwrap();

        let destination = "GDJJRRMBK4IWLEPJGIE6SXD2LP7REGZODU7WDC3I2D6MR37F4XSHBKX2";
        let asset = Asset::native();

        let mut builder = TransactionBuilder::new(&mut source, Networks::testnet(), None);
        builder
            .fee(100_u32)
            .add_operation(
                Operation::new()
                    .payment(destination, &asset, 1000 * operation::ONE)
                    .unwrap(),
            )
            .set_timeout(TIMEOUT_INFINITE)
            .unwrap();

        // Act
        let transaction = builder.build();

        // Assert - sequence number should be incremented
        assert_eq!(source.sequence_number(), "51");
        assert_eq!(transaction.sequence.unwrap(), "51");
    }

    #[test]
    fn test_multiple_simulations_without_incrementing() {
        // Arrange
        let mut source = Account::new(
            "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ",
            "200",
        )
        .unwrap();

        let destination = "GDJJRRMBK4IWLEPJGIE6SXD2LP7REGZODU7WDC3I2D6MR37F4XSHBKX2";
        let asset = Asset::native();

        let mut builder = TransactionBuilder::new(&mut source, Networks::testnet(), None);
        builder
            .fee(100_u32)
            .add_operation(
                Operation::new()
                    .payment(destination, &asset, 1000 * operation::ONE)
                    .unwrap(),
            )
            .set_timeout(TIMEOUT_INFINITE)
            .unwrap();

        // Act - build multiple times for simulation
        let _tx1 = builder.build_for_simulation();
        let _tx2 = builder.build_for_simulation();
        let _tx3 = builder.build_for_simulation();

        // Assert - sequence number should still be unchanged
        assert_eq!(source.sequence_number(), "200");
    }
}
