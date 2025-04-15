use std::str::FromStr;

use serde::de::IntoDeserializer;

use crate::{
    asset::{Asset, AssetBehavior},
    operation::{self, Operation},
    xdr,
};

impl Operation {
    /// Updates the authorized flag of an existing trustline. This operation can only be performed
    /// by the asset issuer.
    ///
    /// The `flag` can be:
    /// - `1` to authorize to transact,
    /// - `2` to authorize to maintain liabilities only,
    /// - `0` to deauthorize.
    ///
    /// Threshold: Low
    pub fn allow_trust(
        &self,
        account: &str,
        asset_code: &str,
        flag: u32,
    ) -> Result<xdr::Operation, operation::Error> {
        //
        let trustor = xdr::AccountId::from_str(account)
            .map_err(|_| operation::Error::InvalidField("account".into()))?;

        let asset = match asset_code {
            a if a.len() <= 4 => {
                let code = xdr::AssetCode4::from_str(a)
                    .map_err(|_| operation::Error::InvalidField("asset_code".into()))?;
                xdr::AssetCode::CreditAlphanum4(code)
            }
            a if a.len() <= 12 => {
                let code = xdr::AssetCode12::from_str(a)
                    .map_err(|_| operation::Error::InvalidField("asset_code".into()))?;
                xdr::AssetCode::CreditAlphanum12(code)
            }
            _ => return Err(operation::Error::InvalidField("asset_code".into())),
        };

        if flag > 2 {
            return Err(operation::Error::InvalidField("flag".into()));
        }
        let body = xdr::OperationBody::AllowTrust(xdr::AllowTrustOp {
            trustor,
            asset,
            authorize: flag,
        });
        Ok(xdr::Operation {
            source_account: self.source.clone(),
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use hyper::body::Buf;
    use stellar_strkey::Strkey;

    use crate::{
        keypair::{Keypair, KeypairBehavior},
        operation::{self, Operation},
        xdr,
    };

    #[test]
    fn test_allow_trust() {
        let account = Keypair::random().unwrap();
        let issuer = Keypair::random().unwrap();
        let flag = 1;
        let asset_code = "ABC";
        let op = Operation::with_source(&issuer.public_key())
            .unwrap()
            .allow_trust(&account.public_key(), asset_code, flag)
            .unwrap();

        if let xdr::OperationBody::AllowTrust(xdr::AllowTrustOp {
            trustor: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(pk))),
            asset: xdr::AssetCode::CreditAlphanum4(code),
            authorize,
        }) = op.body
        {
            //
            assert_eq!(authorize, flag);
            assert_eq!(&pk.to_vec(), account.raw_public_key());
            let mut expected_code = asset_code.as_bytes().to_vec();
            expected_code.push(0);
            assert_eq!(code.as_slice(), expected_code);
        } else {
            panic!("Fail")
        }
    }
    #[test]
    fn test_allow_trust_12() {
        let account = Keypair::random().unwrap();
        let issuer = Keypair::random().unwrap();
        let flag = 1;
        let asset_code = "ABCDEFGHIJKL";
        let op = Operation::with_source(&issuer.public_key())
            .unwrap()
            .allow_trust(&account.public_key(), asset_code, flag)
            .unwrap();

        if let xdr::OperationBody::AllowTrust(xdr::AllowTrustOp {
            trustor: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(pk))),
            asset: xdr::AssetCode::CreditAlphanum12(code),
            authorize,
        }) = op.body
        {
            //
            assert_eq!(authorize, flag);
            assert_eq!(&pk.to_vec(), account.raw_public_key());
            let mut expected_code = asset_code.as_bytes().to_vec();
            assert_eq!(code.as_slice(), expected_code);
        } else {
            panic!("Fail")
        }
    }
    #[test]
    fn test_allow_trust_too_long() {
        let account = Keypair::random().unwrap();
        let issuer = Keypair::random().unwrap();
        let flag = 1;
        let asset_code = "ABCDEFGHIJKL_";
        let op = Operation::with_source(&issuer.public_key())
            .unwrap()
            .allow_trust(&account.public_key(), asset_code, flag);

        assert_eq!(
            op.err(),
            Some(operation::Error::InvalidField("asset_code".into()))
        );
    }
    #[test]
    fn test_allow_trust_bad_flag() {
        let account = Keypair::random().unwrap();
        let issuer = Keypair::random().unwrap();
        let flag = 3;
        let asset_code = "ABCDEFGHIJKL";
        let op = Operation::with_source(&issuer.public_key())
            .unwrap()
            .allow_trust(&account.public_key(), asset_code, flag);

        assert_eq!(
            op.err(),
            Some(operation::Error::InvalidField("flag".into()))
        );
    }
    #[test]
    fn test_allow_trust_bad_account() {
        let account = Strkey::Contract(stellar_strkey::Contract([0; 32])).to_string();
        let issuer = Keypair::random().unwrap();
        let flag = 3;
        let asset_code = "ABCDEFGHIJKL";
        let op = Operation::with_source(&issuer.public_key())
            .unwrap()
            .allow_trust(&account, asset_code, flag);

        assert_eq!(
            op.err(),
            Some(operation::Error::InvalidField("account".into()))
        );
    }
}
