//! Create a new `Account` object.
//!
//! `Account` represents a single account in the Stellar network and its sequence
//! number. `Account` tracks the sequence number as it is used by `TransactionBuilder`.
//!
use crate::asset::AssetBehavior;
use std::str::FromStr;
use std::{error::Error, ops::AddAssign};
use stellar_strkey::ed25519::{MuxedAccount, PublicKey};

#[derive(Debug, Clone)]
pub struct Account {
    account_id: [u8; 32],
    sequence: i64,
}

// Define a trait for Account behavior
pub trait AccountBehavior {
    fn new(account_id: &str, sequence: &str) -> Result<Self, String>
    where
        Self: Sized;
    fn account_id(&self) -> String;
    fn sequence_number(&self) -> String;
    fn increment_sequence_number(&mut self);
}

impl AccountBehavior for Account {
    /// Creates a new Account
    fn new(account_id: &str, sequence: &str) -> Result<Self, String> {
        let muxed_key = MuxedAccount::from_string(account_id);

        if muxed_key.is_ok() {
            return Err("accountId is an M-address; use MuxedAccount instead".into());
        }

        let key =
            PublicKey::from_string(account_id).map_err(|_| "accountId is invalid".to_string())?;

        let sequence = sequence
            .parse::<i64>()
            .map_err(|_| "sequence is inalid".to_string())?;
        Ok(Self {
            account_id: key.0,
            sequence,
        })
    }

    /// Returns the account identifier
    fn account_id(&self) -> String {
        format!("{}", PublicKey(self.account_id))
    }

    /// Returns the sequence number
    fn sequence_number(&self) -> String {
        self.sequence.to_string()
    }

    /// Increments the sequence number
    fn increment_sequence_number(&mut self) {
        self.sequence += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCOUNT: &str = "GBBM6BKZPEHWYO3E3YKREDPQXMS4VK35YLNU7NFBRI26RAN7GI5POFBB";
    const MUXED_ADDRESS: &str =
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK";
    const UNDERLYING_ACCOUNT: &str = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ";

    #[test]
    fn test_account_constructor_invalid_address() {
        let result = Account::new("GBBB", "100");
        assert!(result.is_err());
        assert_eq!(result.err().unwrap().to_string(), "accountId is invalid")
    }

    #[test]
    fn test_account_constructor_valid() {
        let account = Account::new(ACCOUNT, "100").unwrap();
        assert_eq!(account.account_id(), ACCOUNT);
        assert_eq!(account.sequence_number(), "100");
    }

    #[test]
    fn test_account_constructor_muxed_account() {
        let result = Account::new(MUXED_ADDRESS, "123");
        assert!(result.is_err());
        assert_eq!(
            result.err().unwrap().to_string(),
            "accountId is an M-address; use MuxedAccount instead"
        )
    }

    #[test]
    fn test_account_increment_sequence_number() {
        let mut account = Account::new(
            "GBBM6BKZPEHWYO3E3YKREDPQXMS4VK35YLNU7NFBRI26RAN7GI5POFBB",
            "100",
        )
        .unwrap();

        account.increment_sequence_number();
        assert_eq!(account.sequence_number(), "101");
        account.increment_sequence_number();
        account.increment_sequence_number();
        assert_eq!(account.sequence_number(), "103");
    }
}
