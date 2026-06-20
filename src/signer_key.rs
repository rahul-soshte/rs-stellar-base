use core::panic;
use std::{collections::HashMap, str::FromStr};

use crate::xdr;
use crate::xdr::{SignerKey as XDRSignerKey, SignerKeyEd25519SignedPayload};
use stellar_strkey::{
    ed25519::{PublicKey, SignedPayload},
    HashX, PreAuthTx,
};

pub struct SignerKey;

// Define a trait for SignerKey behavior
pub trait SignerKeyBehavior {
    fn decode_address(address: &str) -> XDRSignerKey;
    fn encode_signer_key(signer_key: &XDRSignerKey) -> String;
}

impl SignerKeyBehavior for SignerKey {
    fn decode_address(address: &str) -> XDRSignerKey {
        let val = stellar_strkey::Strkey::from_string(address);
        if val.is_err() {
            panic!("Invalid Type")
        }

        match val.unwrap() {
            stellar_strkey::Strkey::SignedPayloadEd25519(x) => {
                XDRSignerKey::Ed25519SignedPayload(SignerKeyEd25519SignedPayload {
                    ed25519: xdr::Uint256(x.ed25519),
                    payload: x.payload.try_into().unwrap(),
                })
            }
            stellar_strkey::Strkey::PublicKeyEd25519(x) => XDRSignerKey::Ed25519(xdr::Uint256(x.0)),
            stellar_strkey::Strkey::PreAuthTx(x) => XDRSignerKey::PreAuthTx(xdr::Uint256(x.0)),
            stellar_strkey::Strkey::HashX(x) => XDRSignerKey::HashX(xdr::Uint256(x.0)),
            _ => panic!("Invalid Type"),
        }
    }

    fn encode_signer_key(signer_key: &XDRSignerKey) -> String {
        match signer_key {
            XDRSignerKey::Ed25519(x) => {
                stellar_strkey::Strkey::PublicKeyEd25519(PublicKey::from_payload(&x.0).unwrap())
                    .to_string()
            }
            XDRSignerKey::PreAuthTx(x) => {
                stellar_strkey::Strkey::PreAuthTx(PreAuthTx(x.0)).to_string()
            }
            XDRSignerKey::HashX(x) => stellar_strkey::Strkey::HashX(HashX(x.0)).to_string(),
            XDRSignerKey::Ed25519SignedPayload(x) => {
                stellar_strkey::Strkey::SignedPayloadEd25519(SignedPayload {
                    ed25519: x.ed25519.0,
                    payload: x.payload.clone().into_vec(),
                })
                .to_string()
            }
        }
    }
}

fn assert_panic<F: FnOnce(), S: AsRef<str>>(f: F, expected_msg: S) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    match result {
        Ok(_) => panic!("Function did not panic as expected"),
        Err(err) => {
            if let Some(s) = err.downcast_ref::<&str>() {
                assert!(
                    s.contains(expected_msg.as_ref()),
                    "Unexpected panic message. Got: {}",
                    s
                );
            } else {
                panic!("Unexpected panic type");
            }
        }
    }
}

mod tests {
    use crate::xdr::{ReadXdr, WriteXdr};

    use super::*;
    #[derive(Debug)]
    struct TestCase {
        strkey: &'static str,
        r#type: xdr::SignerKeyType,
    }

    static TEST_CASES: [TestCase; 4] = [
        TestCase {
            strkey: "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ",
            r#type: xdr::SignerKeyType::Ed25519,
        },
        TestCase {
            strkey: "TBU2RRGLXH3E5CQHTD3ODLDF2BWDCYUSSBLLZ5GNW7JXHDIYKXZWHXL7",
            r#type: xdr::SignerKeyType::PreAuthTx,
        },
        TestCase {
            strkey: "XBU2RRGLXH3E5CQHTD3ODLDF2BWDCYUSSBLLZ5GNW7JXHDIYKXZWGTOG",
            r#type: xdr::SignerKeyType::HashX,
        },
        TestCase {
            strkey: "PA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAQACAQDAQCQMBYIBEFAWDANBYHRAEISCMKBKFQXDAMRUGY4DUPB6IBZGM",
            r#type: xdr::SignerKeyType::Ed25519SignedPayload,
        },
    ];

    #[test]
    fn test_encode_decode_roundtrip() {
        for test_case in &TEST_CASES {
            let skey = SignerKey::decode_address(test_case.strkey);

            assert_eq!(skey.discriminant(), test_case.r#type);

            let raw_xdr = skey.to_xdr(xdr::Limits::none()).unwrap();
            let raw_sk = xdr::SignerKey::from_xdr(raw_xdr, xdr::Limits::none()).unwrap();
            assert_eq!(raw_sk, skey);

            let address = SignerKey::encode_signer_key(&skey);
            assert_eq!(address, test_case.strkey);
        }
    }

    #[test]
    fn error_cases_for_invalid_signers() {
        let invalid_signers = &[
            "SAB5556L5AN5KSR5WF7UOEFDCIODEWEO7H2UR4S5R62DFTQOGLKOVZDY",
            "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK",
            "NONSENSE",
        ];

        for strkey in invalid_signers.iter() {
            let scenario_1 = || {
                SignerKey::decode_address(strkey);
            };
            assert_panic(scenario_1, "Invalid Type")
        }
    }

    #[test]
    fn error_cases_for_invalid_strkey() {
        let strkey = "G47QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVP2I";
        let scenario_1 = || {
            SignerKey::decode_address(strkey);
        };
        assert_panic(scenario_1, "Invalid Type")
    }
}
