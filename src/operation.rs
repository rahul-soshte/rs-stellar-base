//! Operations are individual commands that modify the ledger.
use crate::liquidity_pool_asset::LiquidityPoolAssetBehavior;
use crate::utils::decode_encode_muxed_account::decode_address_to_muxed_account_fix_for_g_address;
use crate::xdr;
use crate::xdr::WriteXdr;
use hex_literal::hex;
use num_bigint::BigInt;
use num_bigint::BigUint;
use num_rational::Rational32;
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

const ONE: i32 = 10_000_000;
const MAX_INT64: &str = "9223372036854775807";
pub enum SignerKeyAttrs {
    Ed25519PublicKey(String),
    PreAuthTx(String),
    Sha256Hash(String),
}

pub const AUTH_REQUIRED_FLAG: u32 = 1 << 0;
pub const AUTH_REVOCABLE_FLAG: u32 = 1 << 1;
pub const AUTH_IMMUTABLE_FLAG: u32 = 1 << 2;

pub struct Operation {
    pub op_attrs: Option<MuxedAccount>,
    pub opts: Option<String>,
}

pub struct OpAttributes {
    pub source_account: Option<MuxedAccount>,
}
pub enum Value {
    Single(String),
    Single2(xdr::HostFunction),
    Multiple(Vec<String>),
    MultipleClaimant(Vec<Claimant>),
    MultipleFlag(HashMap<String, Option<bool>>),
    MultipleAuth(Vec<xdr::SorobanAuthorizationEntry>),
}

pub struct PaymentOpts {
    pub destination: String,
    pub asset: Asset,
    pub amount: String,
    pub source: Option<String>,
}

pub trait OperationBehavior {
    fn set_source_account(&mut self, source: Option<&str>);
    fn from_xdr_object(operation: xdr::Operation) -> Result<HashMap<String, Value>, &'static str>;
    fn check_unsigned_int_value<F>(
        name: &str,
        value: &Option<String>,
        is_valid_function: Option<F>,
    ) -> Result<Option<u32>, String>
    where
        F: Fn(u32, &str) -> bool;
}

impl Operation {
    pub fn payment(opts: PaymentOpts) -> Result<xdr::Operation, String> {
        let destination = match decode_address_to_muxed_account_fix_for_g_address(&opts.destination)
        {
            account => account,
            _ => return Err("destination is invalid".to_string()),
        };

        let asset: xdr::Asset = opts.asset.to_xdr_object();
        let amount = match to_xdr_amount(&opts.amount) {
            Ok(amount) => amount,
            Err(e) => return Err(format!("Invalid amount: {}", e)),
        };

        let payment_op = xdr::PaymentOp {
            asset,
            amount,
            destination,
        };

        let body = xdr::OperationBody::Payment(payment_op);

        //TODO: Add Source Account
        // if let Some(source) = opts.source {
        //     match decode_address_to_muxed_account(&source).unwrap() {
        //         Ok(account) => op_attributes.source_account = Some(account),
        //         Err(_) => return Err("Source account is invalid".to_string()),
        //     }
        // }

        Ok(xdr::Operation {
            source_account: None,
            body,
        })
    }
}
impl OperationBehavior for Operation {
    fn set_source_account(&mut self, source: Option<&str>) {
        if let Some(source) = &self.opts {
            match decode_address_to_muxed_account(source) {
                muxed_account => self.op_attrs = Some(muxed_account),
                _ => panic!("Source address is invalid"),
            }
        }
    }

    fn from_xdr_object(operation: xdr::Operation) -> Result<HashMap<String, Value>, &'static str> {
        let mut result: HashMap<String, Value> = HashMap::new();

        if let Some(source_account) = operation.source_account {
            result.insert(
                "source".to_string(),
                Value::Single(encode_muxed_account_to_address(&source_account)),
            );
        }

        match operation.body {
            xdr::OperationBody::CreateAccount(x) => {
                result.insert(
                    "type".to_string(),
                    Value::Single("createAccount".to_string()),
                );
                result.insert(
                    "destination".to_string(),
                    Value::Single(account_id_to_address(&x.destination)),
                );
                result.insert(
                    "startingBalance".to_string(),
                    Value::Single(
                        from_xdr_amount(BigUint::from(x.starting_balance as u64)).to_string(),
                    ),
                );
            }
            xdr::OperationBody::Payment(x) => {
                result.insert("type".to_string(), Value::Single("payment".to_string()));
                result.insert(
                    "destination".to_string(),
                    Value::Single(encode_muxed_account_to_address(&x.destination)),
                );
                result.insert(
                    "asset".to_string(),
                    Value::Single(Asset::from_operation(x.asset).unwrap().to_string()),
                );
                result.insert(
                    "amount".to_string(),
                    Value::Single(from_xdr_amount(BigUint::from(x.amount as u64)).to_string()),
                );
            }
            xdr::OperationBody::PathPaymentStrictReceive(x) => {
                result.insert(
                    "type".to_string(),
                    Value::Single("pathPaymentStrictReceive".to_string()),
                );
                result.insert(
                    "sendAsset".to_string(),
                    Value::Single(Asset::from_operation(x.send_asset).unwrap().to_string()),
                );
                result.insert(
                    "sendMax".to_string(),
                    Value::Single(from_xdr_amount(BigUint::from(x.send_max as u64)).to_string()),
                );
                result.insert(
                    "destination".to_string(),
                    Value::Single(encode_muxed_account_to_address(&x.destination)),
                );
                result.insert(
                    "destAsset".to_string(),
                    Value::Single(Asset::from_operation(x.dest_asset).unwrap().to_string()),
                );
                result.insert(
                    "destAmount".to_string(),
                    Value::Single(from_xdr_amount(BigUint::from(x.dest_amount as u64)).to_string()),
                );
                let mut path_vec = Vec::new();
                for path_key in x.path.iter() {
                    path_vec.push(Asset::from_operation(path_key.clone()).unwrap().to_string());
                }
                result.insert("path".to_string(), Value::Multiple(path_vec));
            }
            xdr::OperationBody::ManageSellOffer(x) => {
                result.insert(
                    "type".to_string(),
                    Value::Single("manageSellOffer".to_string()),
                );
                result.insert(
                    "selling".to_string(),
                    Value::Single(Asset::from_operation(x.selling).unwrap().to_string()),
                );
                result.insert(
                    "buying".to_string(),
                    Value::Single(Asset::from_operation(x.buying).unwrap().to_string()),
                );
                result.insert(
                    "amount".to_string(),
                    Value::Single(from_xdr_amount(BigUint::from(x.amount as u64)).to_string()),
                );
                result.insert("price".to_string(), Value::Single(from_xdr_price(x.price)));
                result.insert("offerId".to_string(), Value::Single(x.offer_id.to_string()));
            }
            xdr::OperationBody::CreatePassiveSellOffer(x) => {
                result.insert(
                    "type".to_string(),
                    Value::Single("createPassiveSellOffer".to_string()),
                );
                result.insert(
                    "selling".to_string(),
                    Value::Single(Asset::from_operation(x.selling).unwrap().to_string()),
                );
                result.insert(
                    "buying".to_string(),
                    Value::Single(Asset::from_operation(x.buying).unwrap().to_string()),
                );
                result.insert(
                    "amount".to_string(),
                    Value::Single(from_xdr_amount(BigUint::from(x.amount as u64)).to_string()),
                );
                result.insert("price".to_string(), Value::Single(from_xdr_price(x.price)));
            }
            xdr::OperationBody::SetOptions(_) => todo!(),
            xdr::OperationBody::ChangeTrust(x) => {
                result.insert("type".to_string(), Value::Single("changeTrust".to_string()));
                match x.line {
                    xdr::ChangeTrustAsset::Native => {
                        result.insert(
                            "line".to_string(),
                            Value::Single(Asset::native().to_string()),
                        );
                    }
                    xdr::ChangeTrustAsset::CreditAlphanum4(x) => {
                        result.insert(
                            "line".to_string(),
                            Value::Single(
                                LiquidityPoolAsset::from_operation(
                                    &xdr::ChangeTrustAsset::CreditAlphanum4(x),
                                )
                                .unwrap()
                                .to_string(),
                            ),
                        );
                    }
                    xdr::ChangeTrustAsset::CreditAlphanum12(x) => {
                        result.insert(
                            "line".to_string(),
                            Value::Single(
                                LiquidityPoolAsset::from_operation(
                                    &xdr::ChangeTrustAsset::CreditAlphanum12(x),
                                )
                                .unwrap()
                                .to_string(),
                            ),
                        );
                    }
                    xdr::ChangeTrustAsset::PoolShare(x) => {
                        result.insert(
                            "line".to_string(),
                            Value::Single(
                                LiquidityPoolAsset::from_operation(
                                    &xdr::ChangeTrustAsset::PoolShare(x),
                                )
                                .unwrap()
                                .to_string(),
                            ),
                        );
                    }
                }
                result.insert(
                    "limit".to_string(),
                    Value::Single(from_xdr_amount(BigUint::from(x.limit as u64)).to_string()),
                );
            }
            xdr::OperationBody::AllowTrust(x) => {
                result.insert("type".to_string(), Value::Single("allowTrust".to_string()));
                result.insert(
                    "trustor".to_string(),
                    Value::Single(account_id_to_address(&x.trustor)),
                );
                let asset_code = match x.asset {
                    xdr::AssetCode::CreditAlphanum4(x) => {
                        x.to_string().trim_end_matches('\0').to_string()
                    }
                    xdr::AssetCode::CreditAlphanum12(x) => {
                        x.to_string().trim_end_matches('\0').to_string()
                    }
                };
                result.insert("assetCode".to_string(), Value::Single(asset_code));
                result.insert(
                    "authorize".to_string(),
                    Value::Single(x.authorize.to_string()),
                );
            }
            xdr::OperationBody::AccountMerge(destination) => {
                result.insert("type".into(), Value::Single("accountMerge".into()));
                result.insert(
                    "destination".into(),
                    Value::Single(encode_muxed_account_to_address(&destination)),
                );
            }
            xdr::OperationBody::Inflation => {
                result.insert("type".to_string(), Value::Single("inflation".to_string()));
            }
            xdr::OperationBody::ManageData(x) => {
                result.insert("type".to_string(), Value::Single("manageData".to_string()));
                let data_name = x.data_name.to_string().trim_end_matches('\0').to_string();
                result.insert("name".to_string(), Value::Single(data_name));
                result.insert(
                    "value".to_string(),
                    Value::Single(x.data_value.unwrap().0.to_string().unwrap()),
                );
            }
            xdr::OperationBody::BumpSequence(x) => {
                result.insert(
                    "type".to_string(),
                    Value::Single("bumpSequence".to_string()),
                );
                result.insert("bumpTo".to_string(), Value::Single(x.bump_to.0.to_string()));
            }
            xdr::OperationBody::ManageBuyOffer(x) => {
                result.insert(
                    "type".to_string(),
                    Value::Single("manageBuyOffer".to_string()),
                );
                result.insert(
                    "selling".to_string(),
                    Value::Single(Asset::from_operation(x.buying).unwrap().to_string()),
                );
                result.insert(
                    "buying".to_string(),
                    Value::Single(Asset::from_operation(x.selling).unwrap().to_string()),
                );
                result.insert(
                    "amount".to_string(),
                    Value::Single(from_xdr_amount(BigUint::from(x.buy_amount as u64)).to_string()),
                );
                result.insert("price".to_string(), Value::Single(from_xdr_price(x.price)));
                result.insert("offerId".to_string(), Value::Single(x.offer_id.to_string()));
            }
            xdr::OperationBody::PathPaymentStrictSend(x) => {
                result.insert(
                    "type".to_string(),
                    Value::Single("pathPaymentStrictSend".to_string()),
                );
                result.insert(
                    "sendAsset".to_string(),
                    Value::Single(Asset::from_operation(x.send_asset).unwrap().to_string()),
                );
                result.insert(
                    "sendAmount".to_string(),
                    Value::Single(from_xdr_amount(BigUint::from(x.send_amount as u64)).to_string()),
                );
                result.insert(
                    "destination".to_string(),
                    Value::Single(encode_muxed_account_to_address(&x.destination)),
                );
                result.insert(
                    "destAsset".to_string(),
                    Value::Single(Asset::from_operation(x.dest_asset).unwrap().to_string()),
                );
                result.insert(
                    "destMin".to_string(),
                    Value::Single(from_xdr_amount(BigUint::from(x.dest_min as u64)).to_string()),
                );
                let mut path_vec = Vec::new();
                for path_key in x.path.iter() {
                    path_vec.push(Asset::from_operation(path_key.clone()).unwrap().to_string());
                }
                result.insert("path".to_string(), Value::Multiple(path_vec));
            }
            xdr::OperationBody::CreateClaimableBalance(x) => {
                result.insert(
                    "type".to_string(),
                    Value::Single("createClaimableBalance".to_string()),
                );
                result.insert(
                    "asset".to_string(),
                    Value::Single(Asset::from_operation(x.asset).unwrap().to_string()),
                );
                result.insert(
                    "amount".to_string(),
                    Value::Single(from_xdr_amount((x.amount as u64).into()).to_string()),
                );
                let mut claimants = Vec::new();
                for val in x.claimants.iter() {
                    claimants.push(Claimant::from_xdr(val.clone()).unwrap());
                }
                result.insert("claimants".to_string(), Value::MultipleClaimant(claimants));
            }
            xdr::OperationBody::ClaimClaimableBalance(x) => {
                result.insert(
                    "type".to_string(),
                    Value::Single("claimClaimableBalance".to_string()),
                );
                result.insert(
                    "balanceId".to_string(),
                    Value::Single(
                        String::from_utf8(x.to_xdr(xdr::Limits::none()).unwrap()).unwrap(),
                    ),
                );
            }
            xdr::OperationBody::BeginSponsoringFutureReserves(x) => {
                result.insert(
                    "type".to_string(),
                    Value::Single("beginSponsoringFutureReserves".to_string()),
                );
                result.insert(
                    "sponsoredId".to_string(),
                    Value::Single(account_id_to_address(&x.sponsored_id)),
                );
            }
            xdr::OperationBody::EndSponsoringFutureReserves => {
                result.insert(
                    "type".to_string(),
                    Value::Single("endSponsoringFutureReserves".to_string()),
                );
            }
            xdr::OperationBody::RevokeSponsorship(x) => {
                result.insert(
                    "type".to_string(),
                    Value::Single("revokeSponsorship".to_string()),
                );
                // result.insert("account".to_string(), Value::Single(x..to_string()));
            }
            xdr::OperationBody::Clawback(_) => todo!(),
            xdr::OperationBody::ClawbackClaimableBalance(_) => todo!(),
            xdr::OperationBody::SetTrustLineFlags(x) => {
                result.insert(
                    "type".to_string(),
                    Value::Single("setTrustlineFlags".to_string()),
                );
                result.insert(
                    "trustor".to_string(),
                    Value::Single(account_id_to_address(&x.trustor)),
                );
                result.insert(
                    "asset".to_string(),
                    Value::Single(Asset::from_operation(x.asset).unwrap().to_string()),
                );
                // result.insert("flags".to_string(), Value::Single(attrs.flags().to_string()));
                let clear = x.clear_flags;
                let set = x.set_flags;

                let mut mapping = HashMap::new();
                mapping.insert("authorized", xdr::TrustLineFlags::AuthorizedFlag);
                mapping.insert(
                    "authorizedToMaintainLiabilities",
                    xdr::TrustLineFlags::AuthorizedToMaintainLiabilitiesFlag,
                );
                mapping.insert(
                    "clawbackEnabled",
                    xdr::TrustLineFlags::TrustlineClawbackEnabledFlag,
                );

                let get_flag_value =
                    |key: &str,
                     sets: u32,
                     clears: u32,
                     mapping: &std::collections::HashMap<&str, xdr::TrustLineFlags>|
                     -> Option<bool> {
                        if let Some(flag) = mapping.get(key) {
                            let bit = match flag {
                                xdr::TrustLineFlags::AuthorizedFlag => 1,
                                xdr::TrustLineFlags::AuthorizedToMaintainLiabilitiesFlag => 2,
                                xdr::TrustLineFlags::TrustlineClawbackEnabledFlag => 4,
                            };

                            if sets & bit != 0 {
                                Some(true)
                            } else if clears & bit != 0 {
                                Some(false)
                            } else {
                                None
                            }
                        } else {
                            None
                        }
                    };

                let mut flags: HashMap<String, Option<bool>> = HashMap::new();
                for flag_name in mapping.keys() {
                    flags.insert(
                        flag_name.to_string(),
                        get_flag_value(flag_name, set, clear, &mapping),
                    );
                }
                result.insert("flags".to_string(), Value::MultipleFlag(flags));
            }
            xdr::OperationBody::LiquidityPoolDeposit(x) => {
                result.insert(
                    "type".to_string(),
                    Value::Single("liquidityPoolDeposit".to_string()),
                );
                result.insert(
                    "liquidityPoolId".to_string(),
                    Value::Single(x.liquidity_pool_id.0.to_string()),
                );
                result.insert(
                    "maxAmountA".to_string(),
                    Value::Single(from_xdr_amount((x.max_amount_a as u64).into()).to_string()),
                );
                result.insert(
                    "maxAmountB".to_string(),
                    Value::Single(from_xdr_amount((x.max_amount_b as u64).into()).to_string()),
                );
                result.insert(
                    "minPrice".to_string(),
                    Value::Single(from_xdr_price(x.min_price)),
                );
                result.insert(
                    "maxPrice".to_string(),
                    Value::Single(from_xdr_price(x.max_price)),
                );
            }
            xdr::OperationBody::LiquidityPoolWithdraw(x) => {
                result.insert(
                    "type".to_string(),
                    Value::Single("liquidityPoolWithdraw".to_string()),
                );
                result.insert(
                    "liquidityPoolId".to_string(),
                    Value::Single(x.liquidity_pool_id.0.to_string()),
                );
                result.insert(
                    "amount".to_string(),
                    Value::Single(from_xdr_amount((x.amount as u64).into()).to_string()),
                );
                result.insert(
                    "minAmountA".to_string(),
                    Value::Single(from_xdr_amount((x.min_amount_a as u64).into()).to_string()),
                );
                result.insert(
                    "minAmountB".to_string(),
                    Value::Single(from_xdr_amount((x.min_amount_b as u64).into()).to_string()),
                );
            }
            xdr::OperationBody::InvokeHostFunction(x) => {
                result.insert(
                    "type".to_string(),
                    Value::Single("invokeHostFunction".to_string()),
                );
                result.insert("func".to_string(), Value::Single2(x.host_function));
                result.insert("auths".to_string(), Value::MultipleAuth(x.auth.to_vec()));
            }
            // xdr::OperationBody::BumpFootprintExpiration(x) => {
            //     result.insert("type".to_string(), Value::Single("bumpFootprintExpiration".to_string()));
            //     result.insert("ledgersToExpire ".to_string(), Value::Single(x.ledgers_to_expire.to_string()));

            // },
            xdr::OperationBody::RestoreFootprint(x) => {
                result.insert(
                    "type".to_string(),
                    Value::Single("restoreFootprint".to_string()),
                );
            }
            xdr::OperationBody::ExtendFootprintTtl(_) => todo!(),
        }

        Ok(result)
    }

    fn check_unsigned_int_value<F>(
        name: &str,
        value: &Option<String>,
        is_valid_function: Option<F>,
    ) -> Result<Option<u32>, String>
    where
        F: Fn(u32, &str) -> bool,
    {
        match value {
            Some(v) => {
                let parsed_value: f64 = v
                    .parse()
                    .map_err(|_| format!("{} value is invalid", name))?;

                match parsed_value {
                    value if value.is_finite() && value.fract() == 0.0 && value >= 0.0 => {
                        let as_u32: u32 = value as u32;
                        if let Some(is_valid) = is_valid_function {
                            if is_valid(as_u32, name) {
                                Ok(Some(as_u32))
                            } else {
                                Err(format!("{} value is invalid", name))
                            }
                        } else {
                            Ok(Some(as_u32))
                        }
                    }
                    _ => Err(format!("{} value is invalid", name)),
                }
            }
            None => Ok(None),
        }
    }
}
/// Validates that a given amount is possible for a Stellar asset.
pub fn is_valid_amount(value: &str, allow_zero: bool) -> bool {
    if !value.is_empty() {
        if let Ok(amount) = BigInt::from_str_radix(value, 10) {
            if !allow_zero && amount.is_zero() {
                return false;
            }

            let max_int64: BigInt = FromPrimitive::from_i64(i64::MAX).unwrap();
            let one = BigInt::one();

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
    let amount = BigInt::from_str_radix(value, 10)?;
    let one = BigInt::one();
    let xdr_amount = amount * &one;
    let xdr_string = xdr_amount.to_string();
    let xdr_int64 = xdr::Int64::from_str(&xdr_string)?;
    Ok(xdr_int64)
}

pub fn from_xdr_amount(value: BigUint) -> f64 {
    // Convert the value to f64, divide by ONE, and keep up to 7 decimal places
    round_to((value.to_f64().unwrap() / ONE as f64), 7)
}

// Utility function to round an f64 to a specific number of decimal places
pub fn round_to(value: f64, decimal_places: u32) -> f64 {
    let multiplier = 10f64.powi(decimal_places as i32);
    (value * multiplier).round() / multiplier
}

fn from_xdr_price(price: xdr::Price) -> String {
    let ratio = Rational32::new(price.n, price.d);
    ratio.to_string()
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
            Ok(SignerKeyAttrs::Ed25519PublicKey(ed25519_public_key))
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

#[cfg(test)]
mod tests {

    use crate::{
        account::Account,
        keypair::{self, Keypair},
        op_list::create_account::create_account,
    };
    use keypair::KeypairBehavior;
    use xdr::{Int64, Operation, OperationBody, ReadXdr};

    use super::*;

    #[test]
    fn create_account_op_test() {
        let destination = "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ".to_string();
        let destination_hex =
            hex!("899b2840ed5636c56ddc5f14b23975f79f1ba2388d2694e4c56ecdddc960e5ef");
        // println!("Destination hex {:?}", destination_hex);
        let starting_balance = "1000".to_string();

        let op = create_account(destination.clone(), starting_balance).unwrap();

        let op = Operation::to_xdr(&op, xdr::Limits::none()).unwrap();
        let op_from = Operation::from_xdr(op.as_slice(), xdr::Limits::none())
            .unwrap()
            .body;

        if let OperationBody::CreateAccount(op) = &op_from {
            assert_eq!(op.starting_balance, 1000);
            let mut result: [u8; 32] = Default::default();
            result[..32].clone_from_slice(&destination_hex);
            let key = Keypair::new(Some(result), None).unwrap();
            let val = key.xdr_public_key();
            assert_eq!(op.destination.0, val);
        } else {
            panic!("op is not the type expected");
        }
    }
}
