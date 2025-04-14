use std::{cmp::Ordering, str::FromStr};

use crate::claimant::ClaimantBehavior;
use crate::keypair::Keypair;
use crate::utils::util::trim_end;
use crate::xdr;
use regex::Regex;
use stellar_strkey::{
    ed25519,
    Strkey::{self, PublicKeyEd25519},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asset {
    pub code: String,
    pub issuer: Option<String>,
}
impl From<&Asset> for xdr::TrustLineAsset {
    fn from(value: &Asset) -> Self {
        value.to_trust_line_xdr_object()
    }
}
impl From<Asset> for xdr::TrustLineAsset {
    fn from(value: Asset) -> Self {
        value.to_trust_line_xdr_object()
    }
}
impl From<&Asset> for xdr::ChangeTrustAsset {
    fn from(value: &Asset) -> Self {
        value.to_change_trust_xdr_object()
    }
}
impl From<Asset> for xdr::ChangeTrustAsset {
    fn from(value: Asset) -> Self {
        value.to_change_trust_xdr_object()
    }
}

// Define a trait for Asset behavior
pub trait AssetBehavior {
    fn new(code: &str, issuer: Option<&str>) -> Result<Self, String>
    where
        Self: Sized;
    fn from_operation(asset_xdr: xdr::Asset) -> Result<Self, String>
    where
        Self: Sized;
    fn to_xdr_object(&self) -> xdr::Asset;
    fn to_change_trust_xdr_object(&self) -> xdr::ChangeTrustAsset;
    fn to_trust_line_xdr_object(&self) -> xdr::TrustLineAsset;
    fn _to_trustline_xdr_object(&self) -> xdr::TrustLineAsset;
    fn _to_change_trust_xdr_object(&self) -> xdr::ChangeTrustAsset;
    fn _to_xdr_object(&self) -> xdr::Asset;
    fn ascii_compare(a: &str, b: &str) -> i32;
    fn native() -> Self
    where
        Self: Sized;
    fn is_native(&self) -> bool;
    fn compare(asset_a: &Self, asset_b: &Self) -> i32
    where
        Self: Sized;
    fn get_asset_type(&self) -> String;
    fn get_raw_asset_type(&self) -> Result<xdr::AssetType, String>;
    fn equals(&self, asset: &Self) -> bool;
    fn get_code(&self) -> Option<String>;
    fn get_issuer(&self) -> Option<String>;
    fn to_string_asset(&self) -> String;
}

impl AssetBehavior for Asset {
    fn new(code: &str, issuer: Option<&str>) -> Result<Self, String> {
        if !Regex::new(r"^[a-zA-Z0-9]{1,12}$").unwrap().is_match(code) {
            return Err(
                "Asset code is invalid (maximum alphanumeric, 12 characters at max)".to_string(),
            );
        }

        if code.to_lowercase() != "xlm" && issuer.is_none() {
            return Err("Issuer cannot be null".to_string());
        }

        if let Some(issuer) = issuer {
            if Strkey::from_str(issuer).is_err() {
                return Err("Not a valid ed25519 public key".to_string());
            }
        }

        let code = if code.to_lowercase() == "xlm" {
            "XLM".to_string()
        } else {
            code.to_string()
        };

        Ok(Self {
            code,
            issuer: issuer.map(String::from),
        })
    }

    fn from_operation(asset_xdr: xdr::Asset) -> Result<Asset, String> {
        match asset_xdr {
            xdr::Asset::Native => Ok(Asset::native()),
            xdr::Asset::CreditAlphanum4(alpha_num_4) => {
                let anum = alpha_num_4;
                let issuer = Some(anum.issuer.0);
                let issuer = if let Some(xdr::PublicKey::PublicKeyTypeEd25519(inner)) = issuer {
                    Some(ed25519::PublicKey(inner.0).to_string())
                } else {
                    None
                };
                let code = trim_end(
                    String::from_utf8(anum.asset_code.as_slice().into()).unwrap(),
                    '\0',
                );
                Ok(Asset::new(&code, issuer.as_deref())?)
            }
            xdr::Asset::CreditAlphanum12(alpha_num_12) => {
                let anum = alpha_num_12;
                let issuer = Some(anum.issuer.0);
                let issuer = if let Some(xdr::PublicKey::PublicKeyTypeEd25519(inner)) = issuer {
                    Some(ed25519::PublicKey(inner.0).to_string())
                } else {
                    None
                };

                let code = trim_end(
                    String::from_utf8(anum.asset_code.as_slice().into()).unwrap(),
                    '\0',
                );
                Ok(Asset::new(&code, issuer.as_deref())?)
            }
            _ => Err(format!("Invalid asset type: {:?}", asset_xdr)),
        }
    }

    fn to_xdr_object(&self) -> xdr::Asset {
        self._to_xdr_object()
    }

    fn to_change_trust_xdr_object(&self) -> xdr::ChangeTrustAsset {
        self._to_change_trust_xdr_object()
    }

    fn to_trust_line_xdr_object(&self) -> xdr::TrustLineAsset {
        self._to_trustline_xdr_object()
    }

    fn _to_trustline_xdr_object(&self) -> xdr::TrustLineAsset {
        if self.is_native() {
            xdr::TrustLineAsset::Native
        } else if self.code.len() <= 4 {
            let pad_length = if self.code.len() <= 4 { 4 } else { 12 };
            let padded_code =
                format!("{:width$}", self.code, width = pad_length).replace(' ', "\0");

            let mut asset_code: [u8; 4] = [0; 4];

            for (i, b) in self.code.as_bytes().iter().enumerate() {
                asset_code[i] = *b;
            }

            let addr = xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(
                ed25519::PublicKey::from_string(&self.issuer.clone().unwrap())
                    .unwrap()
                    .0,
            )));

            xdr::TrustLineAsset::CreditAlphanum4(xdr::AlphaNum4 {
                asset_code: xdr::AssetCode4(asset_code),
                issuer: addr.clone(),
            })
        } else {
            let pad_length = if self.code.len() <= 4 { 4 } else { 12 };
            let padded_code =
                format!("{:width$}", self.code, width = pad_length).replace(' ', "\0");

            let mut asset_code: [u8; 12] = [0; 12];

            for (i, b) in self.code.as_bytes().iter().enumerate() {
                asset_code[i] = *b;
            }

            let addr = xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(
                ed25519::PublicKey::from_string(&self.issuer.clone().unwrap())
                    .unwrap()
                    .0,
            )));

            xdr::TrustLineAsset::CreditAlphanum12(xdr::AlphaNum12 {
                asset_code: xdr::AssetCode12(asset_code),
                issuer: addr.clone(),
            })
        }
    }

    fn _to_change_trust_xdr_object(&self) -> xdr::ChangeTrustAsset {
        if self.is_native() {
            xdr::ChangeTrustAsset::Native
        } else if self.code.len() <= 4 {
            let pad_length = if self.code.len() <= 4 { 4 } else { 12 };
            let padded_code =
                format!("{:width$}", self.code, width = pad_length).replace(' ', "\0");

            let mut asset_code: [u8; 4] = [0; 4];

            for (i, b) in self.code.as_bytes().iter().enumerate() {
                asset_code[i] = *b;
            }

            let addr = xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(
                ed25519::PublicKey::from_string(&self.issuer.clone().unwrap())
                    .unwrap()
                    .0,
            )));

            xdr::ChangeTrustAsset::CreditAlphanum4(xdr::AlphaNum4 {
                asset_code: xdr::AssetCode4(asset_code),
                issuer: addr.clone(),
            })
        } else {
            let pad_length = if self.code.len() <= 4 { 4 } else { 12 };
            let padded_code =
                format!("{:width$}", self.code, width = pad_length).replace(' ', "\0");

            let mut asset_code: [u8; 12] = [0; 12];

            for (i, b) in self.code.as_bytes().iter().enumerate() {
                asset_code[i] = *b;
            }

            let addr = xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(
                ed25519::PublicKey::from_string(&self.issuer.clone().unwrap())
                    .unwrap()
                    .0,
            )));

            xdr::ChangeTrustAsset::CreditAlphanum12(xdr::AlphaNum12 {
                asset_code: xdr::AssetCode12(asset_code),
                issuer: addr.clone(),
            })
        }
    }

    fn _to_xdr_object(&self) -> xdr::Asset {
        if self.is_native() {
            xdr::Asset::Native
        } else if self.code.len() <= 4 {
            let pad_length = if self.code.len() <= 4 { 4 } else { 12 };

            let mut asset_code: [u8; 4] = [0; 4];

            for (i, b) in self.code.as_bytes().iter().enumerate() {
                asset_code[i] = *b;
            }

            let addr = xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(
                ed25519::PublicKey::from_string(&self.issuer.clone().unwrap())
                    .unwrap()
                    .0,
            )));

            // println!("Padded Code {:?}", padded_code);

            xdr::Asset::CreditAlphanum4(xdr::AlphaNum4 {
                asset_code: xdr::AssetCode4(asset_code),
                issuer: addr.clone(),
            })
        } else {
            let pad_length = if self.code.len() <= 4 { 4 } else { 12 };
            let padded_code =
                format!("{:width$}", self.code, width = pad_length).replace(' ', "\0");
            let mut asset_code: [u8; 12] = [0; 12];

            for (i, b) in self.code.as_bytes().iter().enumerate() {
                asset_code[i] = *b;
            }

            let addr = xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(
                ed25519::PublicKey::from_string(&self.issuer.clone().unwrap())
                    .unwrap()
                    .0,
            )));

            xdr::Asset::CreditAlphanum12(xdr::AlphaNum12 {
                asset_code: xdr::AssetCode12(asset_code),
                issuer: addr.clone(),
            })
        }
    }

    fn ascii_compare(a: &str, b: &str) -> i32 {
        let result = a.as_bytes().cmp(b.as_bytes());
        match result {
            Ordering::Less => -1,
            Ordering::Equal => 0,
            Ordering::Greater => 1,
        }
    }

    fn native() -> Self {
        // The native asset in Stellar is represented by the code 'XLM' with no issuer.
        Self {
            code: "XLM".to_string(),
            issuer: None,
        }
    }

    fn is_native(&self) -> bool {
        self.issuer.is_none()
    }

    fn compare(asset_a: &Asset, asset_b: &Asset) -> i32 {
        if asset_a.equals(asset_b) {
            return 0;
        }

        let xdr_a_type = asset_a.get_raw_asset_type();
        let xdr_b_type = asset_b.get_raw_asset_type();

        if xdr_a_type != xdr_b_type {
            let result = xdr_a_type.cmp(&xdr_b_type);
            if result == Ordering::Less {
                return -1;
            } else {
                return 1;
            }
        }

        let code_compare = Self::ascii_compare(
            &asset_a.get_code().unwrap_or("".to_owned()),
            &asset_b.get_code().unwrap_or("".to_owned()),
        );
        if code_compare != 0 {
            return code_compare;
        }

        Self::ascii_compare(
            &asset_a.get_issuer().unwrap_or("".to_owned()),
            &asset_b.get_issuer().unwrap_or("".to_owned()),
        )
    }

    fn get_asset_type(&self) -> String {
        match self.get_raw_asset_type() {
            Ok(xdr::AssetType::Native) => "native".to_string(),
            Ok(xdr::AssetType::CreditAlphanum4) => "credit_alphanum4".to_string(),
            Ok(xdr::AssetType::CreditAlphanum12) => "credit_alphanum12".to_string(),
            _ => "unknown".to_string(),
        }
    }

    fn get_raw_asset_type(&self) -> Result<xdr::AssetType, String> {
        if self.is_native() {
            Ok(xdr::AssetType::Native)
        } else if self.code.len() <= 4 {
            Ok(xdr::AssetType::CreditAlphanum4)
        } else {
            Ok(xdr::AssetType::CreditAlphanum12)
        }
    }

    fn equals(&self, asset: &Asset) -> bool {
        self.get_code() == asset.get_code() && self.get_issuer() == asset.get_issuer()
    }

    fn get_code(&self) -> Option<String> {
        Some(self.code.clone())
    }

    fn get_issuer(&self) -> Option<String> {
        self.issuer.clone()
    }

    fn to_string_asset(&self) -> String {
        if self.is_native() {
            return "native".to_string();
        }

        match (self.get_code(), self.get_issuer()) {
            (Some(code), Some(issuer)) => format!("{}:{}", code, issuer),
            _ => "".to_string(),
        }
    }
}

impl ToString for Asset {
    fn to_string(&self) -> String {
        if self.is_native() {
            return "native".to_string();
        }

        match (self.get_code(), self.get_issuer()) {
            (Some(code), Some(issuer)) => format!("{}:{}", code, issuer),
            _ => "".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::xdr::WriteXdr as _;

    use super::Asset;
    use crate::asset::AssetBehavior;
    use crate::xdr;

    #[test]
    fn test_no_issuer_for_non_xlm_asset() {
        let err_val = Asset::new("USD", None).unwrap_err();
        assert_eq!(err_val, "Issuer cannot be null");
    }

    #[test]
    fn test_invalid_asset_code() {
        let err_val = Asset::new(
            "",
            Some("GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ"),
        )
        .unwrap_err();
        assert_eq!(
            err_val,
            "Asset code is invalid (maximum alphanumeric, 12 characters at max)"
        );
        let err_val = super::Asset::new(
            "1234567890123",
            Some("GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ"),
        )
        .unwrap_err();
        assert_eq!(
            err_val,
            "Asset code is invalid (maximum alphanumeric, 12 characters at max)"
        );
        let err_val = Asset::new(
            "ab_",
            Some("GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ"),
        )
        .unwrap_err();
        assert_eq!(
            err_val,
            "Asset code is invalid (maximum alphanumeric, 12 characters at max)"
        );
    }

    #[test]
    fn test_native_asset_code() {
        let asset = Asset::native();
        assert_eq!(asset.get_code().unwrap(), "XLM");
    }

    #[test]
    fn test_asset_code() {
        let issuer = "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ";
        let asset = Asset::new("USD", Some(issuer)).unwrap();
        assert_eq!(asset.get_code().unwrap(), "USD");
    }

    #[test]
    fn test_native_asset_issuer() {
        let asset = Asset::native();
        assert!(asset.get_issuer().is_none());
    }

    #[test]
    fn test_non_native_asset_issuer() {
        let issuer = "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ";
        let asset = Asset::new("USD", Some(issuer)).unwrap();
        assert_eq!(asset.get_issuer(), Some(issuer.to_string()));
    }

    #[test]
    fn test_native_asset_type() {
        let asset = Asset::native();
        assert_eq!(asset.get_asset_type(), "native");
    }

    #[test]
    fn test_credit_alphanum4_asset_type() {
        let issuer = "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ";
        let asset = Asset::new("ABCD", Some(issuer)).unwrap();
        assert_eq!(asset.get_asset_type(), "credit_alphanum4");
    }

    #[test]
    fn test_credit_alphanum12_asset_type() {
        let issuer = "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ";
        let asset = Asset::new("ABCDEF", Some(issuer)).unwrap();
        assert_eq!(asset.get_asset_type(), "credit_alphanum12");
    }

    #[test]
    fn test_parse_native_asset() {
        let asset = Asset::native();

        // Test toXDRObject() for Asset
        let xdr = asset.to_xdr_object();

        assert_eq!(
            String::from_utf8(xdr.to_xdr(xdr::Limits::none()).unwrap()),
            String::from_utf8([0u8, 0u8, 0u8, 0u8].to_vec())
        );

        let xdr = asset.to_change_trust_xdr_object();
        assert_eq!(
            String::from_utf8(xdr.to_xdr(xdr::Limits::none()).unwrap()),
            String::from_utf8([0u8, 0u8, 0u8, 0u8].to_vec())
        );

        // // Test toTrustLineXDRObject() for TrustLineAsset
        let xdr = asset.to_trust_line_xdr_object();
        assert_eq!(
            String::from_utf8(xdr.to_xdr(xdr::Limits::none()).unwrap()),
            String::from_utf8([0u8, 0u8, 0u8, 0u8].to_vec())
        );
    }

    #[test]
    fn test_parse_3_alphanum_asset() {
        let issuer = "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ";
        let asset = Asset::new("USD", Some(issuer)).unwrap();
        let xdr = asset.to_xdr_object();

        match xdr {
            xdr::Asset::CreditAlphanum4(x) => {
                assert_eq!(hex::encode(x.asset_code), hex::encode("USD\0".to_string()))
            }
            _ => panic!("Error"),
        }

        let xdr = asset.to_change_trust_xdr_object();
        match xdr {
            xdr::ChangeTrustAsset::CreditAlphanum4(x) => {
                assert_eq!(hex::encode(x.asset_code), hex::encode("USD\0".to_string()))
            }
            _ => panic!("Error"),
        }

        let xdr = asset.to_trust_line_xdr_object();
        match xdr {
            xdr::TrustLineAsset::CreditAlphanum4(x) => {
                assert_eq!(hex::encode(x.asset_code), hex::encode("USD\0".to_string()))
            }
            _ => panic!("Error"),
        }
    }

    #[test]
    fn test_parse_4_alphanum_asset() {
        let issuer = "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ";
        let asset = Asset::new("BART", Some(issuer)).unwrap();
        let xdr = asset.to_xdr_object();

        match xdr {
            xdr::Asset::CreditAlphanum4(x) => {
                assert_eq!(hex::encode(x.asset_code), hex::encode("BART".to_string()))
            }
            _ => panic!("Error"),
        }

        let xdr = asset.to_change_trust_xdr_object();
        match xdr {
            xdr::ChangeTrustAsset::CreditAlphanum4(x) => {
                assert_eq!(hex::encode(x.asset_code), hex::encode("BART".to_string()))
            }
            _ => panic!("Error"),
        }

        let xdr = asset.to_trust_line_xdr_object();
        match xdr {
            xdr::TrustLineAsset::CreditAlphanum4(x) => {
                assert_eq!(hex::encode(x.asset_code), hex::encode("BART".to_string()))
            }
            _ => panic!("Error"),
        }
    }

    #[test]
    fn test_parse_5_alphanum_asset() {
        let issuer = "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ";
        let asset = Asset::new("12345", Some(issuer)).unwrap();
        let xdr = asset.to_xdr_object();

        match xdr {
            xdr::Asset::CreditAlphanum12(x) => assert_eq!(
                hex::encode(x.asset_code),
                hex::encode("12345\0\0\0\0\0\0\0".to_string())
            ),
            _ => panic!("Error"),
        }

        let xdr = asset.to_change_trust_xdr_object();
        match xdr {
            xdr::ChangeTrustAsset::CreditAlphanum12(x) => assert_eq!(
                hex::encode(x.asset_code),
                hex::encode("12345\0\0\0\0\0\0\0".to_string())
            ),
            _ => panic!("Error"),
        }

        let xdr = asset.to_trust_line_xdr_object();
        match xdr {
            xdr::TrustLineAsset::CreditAlphanum12(x) => assert_eq!(
                hex::encode(x.asset_code),
                hex::encode("12345\0\0\0\0\0\0\0".to_string())
            ),
            _ => panic!("Error"),
        }
    }

    #[test]
    fn test_parse_12_alphanum_asset() {
        let issuer = "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ";
        let asset = Asset::new("123456789012", Some(issuer)).unwrap();
        let xdr = asset.to_xdr_object();

        match xdr {
            xdr::Asset::CreditAlphanum12(x) => assert_eq!(
                hex::encode(x.asset_code),
                hex::encode("123456789012".to_string())
            ),
            _ => panic!("Error"),
        }

        let xdr = asset.to_change_trust_xdr_object();
        match xdr {
            xdr::ChangeTrustAsset::CreditAlphanum12(x) => assert_eq!(
                hex::encode(x.asset_code),
                hex::encode("123456789012".to_string())
            ),
            _ => panic!("Error"),
        }

        let xdr = asset.to_trust_line_xdr_object();
        match xdr {
            xdr::TrustLineAsset::CreditAlphanum12(x) => assert_eq!(
                hex::encode(x.asset_code),
                hex::encode("123456789012".to_string())
            ),
            _ => panic!("Error"),
        }
    }

    #[test]
    fn test_parse_xdr_asset() {
        let xdr = xdr::Asset::Native;
        let asset = Asset::from_operation(xdr).unwrap();
        assert!(asset.is_native());

        let issuer = "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ";
        let addr = xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(
            stellar_strkey::ed25519::PublicKey::from_string(issuer)
                .unwrap()
                .0,
        )));

        let mut asset_code: [u8; 4] = [0; 4];

        for (i, b) in "KHL".as_bytes().iter().enumerate() {
            asset_code[i] = *b;
        }
        let xdr = xdr::Asset::CreditAlphanum4(xdr::AlphaNum4 {
            asset_code: xdr::AssetCode4(asset_code),
            issuer: addr.clone(),
        });

        let asset = Asset::from_operation(xdr).unwrap();

        assert_eq!("KHL", asset.get_code().unwrap());
        assert_eq!(issuer.to_string(), asset.get_issuer().unwrap());
    }

    #[test]
    fn test_parse_12_alphanum_xdr_asset() {
        let issuer = "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ";
        let addr = xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(
            stellar_strkey::ed25519::PublicKey::from_string(issuer)
                .unwrap()
                .0,
        )));
        let mut asset_code: [u8; 12] = [0; 12];

        for (i, b) in "KHLTOKEN".as_bytes().iter().enumerate() {
            asset_code[i] = *b;
        }
        let xdr = xdr::Asset::CreditAlphanum12(xdr::AlphaNum12 {
            asset_code: xdr::AssetCode12(asset_code),
            issuer: addr.clone(),
        });

        let asset = Asset::from_operation(xdr).unwrap();
        assert_eq!("KHLTOKEN", asset.get_code().unwrap());
        assert_eq!(issuer.to_string(), asset.get_issuer().unwrap());
    }

    #[test]
    fn test_to_string_native() {
        let asset = Asset::native();
        assert_eq!(asset.to_string(), "native");
    }

    #[test]
    fn test_to_string_non_native() {
        let asset = Asset::new(
            "USD",
            Some("GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ"),
        )
        .unwrap();
        assert_eq!(
            asset.to_string(),
            "USD:GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ"
        );
    }

    #[test]
    fn test_compare_works() {
        let asset_a = Asset::new(
            "ARST",
            Some("GB7TAYRUZGE6TVT7NHP5SMIZRNQA6PLM423EYISAOAP3MKYIQMVYP2JO"),
        )
        .unwrap();

        let asset_b = Asset::new(
            "USD",
            Some("GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ"),
        )
        .unwrap();

        Asset::compare(&asset_a, &asset_b);
    }

    #[test]
    fn test_compare_equal_assets() {
        let xlm = Asset::native();
        let asset_a = Asset::new(
            "ARST",
            Some("GB7TAYRUZGE6TVT7NHP5SMIZRNQA6PLM423EYISAOAP3MKYIQMVYP2JO"),
        )
        .unwrap();

        let asset_b = Asset::new(
            "USD",
            Some("GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ"),
        )
        .unwrap();

        // println!("Result {:?}",Asset::compare(&xlm.clone(), &xlm).);
        assert_eq!(Asset::compare(&xlm.clone(), &xlm), 0);
        assert_eq!(Asset::compare(&asset_a.clone(), &asset_a), 0);
        assert_eq!(Asset::compare(&asset_b.clone(), &asset_b), 0);
    }

    #[test]
    fn test_compare_assets() {
        let xlm = Asset::native();
        let asset_a = Asset::new(
            "ARST",
            Some("GB7TAYRUZGE6TVT7NHP5SMIZRNQA6PLM423EYISAOAP3MKYIQMVYP2JO"),
        )
        .unwrap();

        let asset_b = Asset::new(
            "ARSTANUM12",
            Some("GB7TAYRUZGE6TVT7NHP5SMIZRNQA6PLM423EYISAOAP3MKYIQMVYP2JO"),
        )
        .unwrap();

        // println!("Result {:?}",Asset::compare(&xlm.clone(), &xlm).);
        assert_eq!(Asset::compare(&xlm.clone(), &xlm), 0);
        assert_eq!(Asset::compare(&xlm.clone(), &asset_a), -1);
        assert_eq!(Asset::compare(&xlm.clone(), &asset_b), -1);

        assert_eq!(Asset::compare(&asset_a.clone(), &xlm), 1);
        assert_eq!(Asset::compare(&asset_a.clone(), &asset_a), 0);
        assert_eq!(Asset::compare(&asset_a.clone(), &asset_b), -1);

        assert_eq!(Asset::compare(&asset_b.clone(), &xlm), 1);
        assert_eq!(Asset::compare(&asset_b.clone(), &asset_a), 1);
        assert_eq!(Asset::compare(&asset_b.clone(), &asset_b), 0);
    }

    #[test]
    fn test_compare_asset() {
        let asset_arst = Asset::new(
            "ARST",
            Some("GB7TAYRUZGE6TVT7NHP5SMIZRNQA6PLM423EYISAOAP3MKYIQMVYP2JO"),
        )
        .unwrap();

        let asset_usdx = Asset::new(
            "USDA",
            Some("GB7TAYRUZGE6TVT7NHP5SMIZRNQA6PLM423EYISAOAP3MKYIQMVYP2JO"),
        )
        .unwrap();

        // println!("Result {:?}",Asset::compare(&xlm.clone(), &xlm).);
        assert_eq!(Asset::compare(&asset_arst.clone(), &asset_arst), 0);
        assert_eq!(Asset::compare(&asset_arst.clone(), &asset_usdx), -1);

        assert_eq!(Asset::compare(&asset_usdx.clone(), &asset_arst), 1);
        assert_eq!(Asset::compare(&asset_usdx.clone(), &asset_usdx), 0);

        let asset_lower = Asset::new(
            "aRST",
            Some("GB7TAYRUZGE6TVT7NHP5SMIZRNQA6PLM423EYISAOAP3MKYIQMVYP2JO"),
        )
        .unwrap();

        assert_eq!(Asset::compare(&asset_arst.clone(), &asset_lower), -1);
        assert_eq!(Asset::compare(&asset_lower.clone(), &asset_arst), 1);
    }

    #[test]
    fn test_compare_asset_issuers() {
        let asset_a = Asset::new(
            "ARST",
            Some("GB7TAYRUZGE6TVT7NHP5SMIZRNQA6PLM423EYISAOAP3MKYIQMVYP2JO"),
        )
        .unwrap();

        let asset_b = Asset::new(
            "ARST",
            Some("GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ"),
        )
        .unwrap();

        assert_eq!(Asset::compare(&asset_a.clone(), &asset_b), -1);
        assert_eq!(Asset::compare(&asset_a.clone(), &asset_a), 0);

        assert_eq!(Asset::compare(&asset_b.clone(), &asset_a), 1);
        assert_eq!(Asset::compare(&asset_b.clone(), &asset_b), 0);
    }

    #[test]
    fn test_compare_upper_lower() {
        let asset_a = Asset::new(
            "B",
            Some("GA7NLOF4EHWMJF6DBXXV2H6AYI7IHYWNFZR6R52BYBLY7TE5Q74AIDRA"),
        )
        .unwrap();

        let asset_b = Asset::new(
            "a",
            Some("GA7NLOF4EHWMJF6DBXXV2H6AYI7IHYWNFZR6R52BYBLY7TE5Q74AIDRA"),
        )
        .unwrap();

        assert_eq!(Asset::compare(&asset_a.clone(), &asset_b), -1);
    }
}
