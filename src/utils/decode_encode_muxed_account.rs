use crate::muxed_account;
use crate::xdr;
use std::str::FromStr;
use stellar_strkey::ed25519::{MuxedAccount, PublicKey};
use stellar_strkey::Strkey::MuxedAccountEd25519;

pub fn decode_address_to_muxed_account(address: &str) -> MuxedAccount {
    if MuxedAccount::from_str(address).is_ok() {
        decode_address_fully_to_muxed_account(address);
    }

    MuxedAccount::from_string(address).unwrap()
}

// TODO: 'G..' address was not working for payment Op, need to make different function, with better name
pub fn decode_address_to_muxed_account_fix_for_g_address(address: &str) -> xdr::MuxedAccount {
    if MuxedAccount::from_str(address).is_ok() {
        let val = decode_address_fully_to_muxed_account(address);
        return val;
    }

    xdr::MuxedAccount::from_str(address).unwrap()
}

pub fn encode_muxed_account(address: &str, id: &str) -> xdr::MuxedAccount {
    let key = PublicKey::from_string(address);

    if key.is_err() {
        panic!("address should be a Stellar account ID (G...)");
    }
    if id.parse::<u64>().is_err() {
        panic!("id should be a string representing a number (uint64)");
    }

    let vv = key.clone().unwrap().0;

    xdr::MuxedAccount::MuxedEd25519(xdr::MuxedAccountMed25519 {
        id: id.parse::<u64>().unwrap(),
        ed25519: xdr::Uint256(vv),
    })
}

pub fn encode_muxed_account_to_address(muxed_account: &xdr::MuxedAccount) -> String {
    if muxed_account.discriminant() == xdr::CryptoKeyType::MuxedEd25519 {
        return _encode_muxed_account_fully_to_address(muxed_account);
    }

    let inner_value = match muxed_account {
        xdr::MuxedAccount::Ed25519(inner) => inner,
        _ => panic!("Expected Ed25519 variant"),
    };

    format!("{}", PublicKey::from_payload(&inner_value.0).unwrap())
}
pub fn decode_address_fully_to_muxed_account(address: &str) -> xdr::MuxedAccount {
    let binding = MuxedAccount::from_str(address).unwrap();
    let id = xdr::Uint64::from_str(&binding.id.to_string()).unwrap();
    let key = binding.ed25519;
    xdr::MuxedAccount::MuxedEd25519(xdr::MuxedAccountMed25519 {
        id,
        ed25519: xdr::Uint256(key),
    })
}

pub fn _encode_muxed_account_fully_to_address(muxed_account: &xdr::MuxedAccount) -> String {
    if muxed_account.discriminant() == xdr::CryptoKeyType::Ed25519 {
        return encode_muxed_account_to_address(muxed_account);
    }

    let inner_value = match muxed_account {
        xdr::MuxedAccount::MuxedEd25519(inner) => inner,
        _ => panic!("Expected Ed25519 variant"),
    };

    let key = &inner_value.ed25519.0;

    let muxed_account = MuxedAccount {
        ed25519: inner_value.ed25519.0,
        id: inner_value.id,
    };

    let strkey = MuxedAccountEd25519(muxed_account);

    let str_result = format!("{strkey}");

    str_result
}

pub fn extract_base_address(address: &str) -> Result<String, Box<dyn std::error::Error>> {
    let key = PublicKey::from_string(address);

    if key.is_ok() {
        return Ok(address.to_string());
    }

    let key = MuxedAccount::from_string(address);
    if key.is_err() {
        return Err(format!("expected muxed account (M...), got {}", address).into());
    }
    let muxed_account = decode_address_to_muxed_account(address);
    let ed25519_key = muxed_account.ed25519;
    let encoded_ed25519 = PublicKey::from_payload(&ed25519_key).unwrap();
    Ok(format!("{encoded_ed25519}"))
}
