//! Operations are individual commands that modify the ledger.
use crate::liquidity_pool_asset::LiquidityPoolAssetBehavior;
use crate::utils::decode_encode_muxed_account::decode_address_to_muxed_account_fix_for_g_address;
use crate::xdr;
use crate::xdr::WriteXdr;
use num_traits::identities::One;
use num_traits::ToPrimitive;
use num_traits::{FromPrimitive, Num, Signed, Zero};
use std::collections::HashMap;
use std::hash::Hash;
use std::str::FromStr;
use stellar_strkey::ed25519::{MuxedAccount, PublicKey};

use crate::asset::Asset;
use crate::asset::AssetBehavior;
use crate::claimant::Claimant;
use crate::claimant::ClaimantBehavior;
use crate::liquidity_pool_asset::LiquidityPoolAsset;
use crate::utils::decode_encode_muxed_account::{
    decode_address_to_muxed_account, encode_muxed_account_to_address,
};

pub use super::op_list::set_options::AccountFlags;
pub use super::op_list::set_trustline_flags::TrustlineFlags;

pub const ONE: i64 = 10_000_000;
const MAX_INT64: &str = "9223372036854775807";
pub enum SignerKeyAttrs {
    Ed25519PublicKey(String),
    PreAuthTx(String),
    Sha256Hash(String),
}

pub struct Operation {
    pub source: Option<xdr::MuxedAccount>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    InvalidField(String),
    InvalidAmount(i64),
    InvalidPrice(i32, i32),
}

impl Operation {
    pub fn new() -> Self {
        Self { source: None }
    }

    pub fn with_source(source: &str) -> Result<Self, Error> {
        Ok(Self {
            source: Some(
                xdr::MuxedAccount::from_str(source)
                    .map_err(|_| Error::InvalidField("source".into()))?,
            ),
        })
    }
}

impl Default for Operation {
    fn default() -> Self {
        Self::new()
    }
}

/// Validates that a given amount is possible for a Stellar asset.
pub fn is_valid_amount(value: &str, allow_zero: bool) -> bool {
    if !value.is_empty() {
        if let Ok(amount) = value.parse::<i64>() {
            if !allow_zero && amount.is_zero() {
                return false;
            }

            let max_int64 = i64::MAX;
            let one = 1i64;

            if amount.is_negative()
                || amount > max_int64
                || amount.to_string().chars().filter(|&c| c == '.').count() > 1
                || amount
                    .to_string()
                    .chars()
                    .skip_while(|&c| c != '.')
                    .skip(1)
                    .count()
                    > 7
            //TODO: Add case for checking infinite number and NaN
            {
                return false;
            }

            return true;
        }
    }

    false
}

/// xdr representation of the amount value
pub fn to_xdr_amount(value: &str) -> Result<xdr::Int64, Box<dyn std::error::Error>> {
    let amount = value.parse::<i64>()?;
    let one = 1i64;
    let xdr_amount = amount * one;
    let xdr_string = xdr_amount.to_string();
    let xdr_int64 = xdr::Int64::from_str(&xdr_string)?;
    Ok(xdr_int64)
}

pub fn from_xdr_amount(value: u64) -> f64 {
    // Convert the value to f64, divide by ONE, and keep up to 7 decimal places
    round_to((value.to_f64().unwrap() / ONE as f64), 7)
}

// Utility function to round an f64 to a specific number of decimal places
pub fn round_to(value: f64, decimal_places: u32) -> f64 {
    let multiplier = 10f64.powi(decimal_places as i32);
    (value * multiplier).round() / multiplier
}

fn account_id_to_address(account_id: &xdr::AccountId) -> String {
    let xdr::PublicKey::PublicKeyTypeEd25519(val) = account_id.0.clone();
    let key: Result<PublicKey, stellar_strkey::DecodeError> =
        PublicKey::from_string(val.to_string().as_str());

    if key.is_ok() {
        val.to_string()
    } else {
        panic!("Invalid account");
    }
}

fn convert_xdr_signer_key_to_object(
    signer_key: &xdr::SignerKeyType,
) -> Result<SignerKeyAttrs, String> {
    match signer_key {
        xdr::SignerKeyType::Ed25519 => {
            let ed25519_public_key = PublicKey::from_string(signer_key.to_string().as_str())
                .unwrap()
                .to_string();
            Ok(SignerKeyAttrs::Ed25519PublicKey(
                ed25519_public_key.as_str().to_owned(),
            ))
        }
        xdr::SignerKeyType::PreAuthTx => Ok(SignerKeyAttrs::PreAuthTx(
            signer_key.to_xdr_base64(xdr::Limits::none()).unwrap(),
        )),
        xdr::SignerKeyType::HashX => Ok(SignerKeyAttrs::Sha256Hash(
            signer_key.to_xdr_base64(xdr::Limits::none()).unwrap(),
        )),
        _ => panic!("Invalid Type"),
    }
}
