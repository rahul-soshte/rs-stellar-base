use std::{ops::BitOr, str::FromStr};

use crate::{
    asset::{Asset, AssetBehavior},
    operation::{self, Operation},
    xdr,
};

#[derive(Debug, Clone, Copy)]
/// Possible flags for [set_trustline_flags](Operation::set_trustline_flags)
pub enum TrustlineFlags {
    /// Authorize the account to perform transactions with the asset
    Authorized = 1,
    /// Authorize the account to maintain liabilities with the asset
    AuthorizedToMaintainLiabilities = 2,
    /// Stop the claimable balances from being 'clawback enabled', this flag can only be cleared
    TrustlineClawbackEnabled = 4,
}

impl BitOr for TrustlineFlags {
    type Output = u32;

    fn bitor(self, rhs: Self) -> Self::Output {
        self as u32 | rhs as u32
    }
}

impl From<TrustlineFlags> for u32 {
    fn from(flag: TrustlineFlags) -> Self {
        flag as u32
    }
}

impl Operation {
    /// Allows issuing account to configure authorization and trustline flags to an asset
    ///
    /// The `set_flags` and `clear_flags` can be built by logical `or` on enum variants
    /// [TrustlineFlags].
    ///
    /// Threshold: Low
    pub fn set_trustline_flags(
        &self,
        account: &str,
        asset: &Asset,
        set_flags: u32,
        clear_flags: u32,
    ) -> Result<xdr::Operation, operation::Error> {
        //
        let trustor = xdr::AccountId::from_str(account)
            .map_err(|_| operation::Error::InvalidField("account".into()))?;

        let body = xdr::OperationBody::SetTrustLineFlags(xdr::SetTrustLineFlagsOp {
            trustor,
            asset: asset.to_xdr_object(),
            clear_flags,
            set_flags,
        });
        Ok(xdr::Operation {
            source_account: self.source.clone(),
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use stellar_strkey::Strkey;

    use crate::{
        asset::{Asset, AssetBehavior},
        keypair::{Keypair, KeypairBehavior},
        operation::{self, Operation},
        xdr,
    };

    use super::TrustlineFlags;

    #[test]
    fn test_set_trustline_flags() {
        let account = Keypair::random().unwrap();
        let issuer = Keypair::random().unwrap();
        let asset = Asset::new("ABC", Some(&issuer.public_key())).unwrap();
        let set_flags: u32 = TrustlineFlags::Authorized.into();
        let clear_flags = TrustlineFlags::AuthorizedToMaintainLiabilities
            | TrustlineFlags::TrustlineClawbackEnabled;
        let op = Operation::new()
            .set_trustline_flags(&account.public_key(), &asset, set_flags, clear_flags)
            .unwrap();

        if let xdr::OperationBody::SetTrustLineFlags(xdr::SetTrustLineFlagsOp {
            trustor: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(pk))),
            asset: xdr_asset,

            clear_flags: cf,
            set_flags: sf,
        }) = op.body
        {
            assert_eq!(&pk.to_vec(), account.raw_public_key());
            assert_eq!(xdr_asset, asset.to_xdr_object());
            assert_eq!(cf, clear_flags);
            assert_eq!(sf, set_flags);

            //
        } else {
            panic!("Fail")
        }
    }
    #[test]
    fn test_set_trustline_flags_bad_account() {
        let account = Strkey::Contract(stellar_strkey::Contract([0; 32])).to_string();
        let issuer = Keypair::random().unwrap();
        let asset = Asset::new("ABC", Some(&issuer.public_key())).unwrap();
        let set_flags: u32 = TrustlineFlags::Authorized.into();
        let clear_flags = TrustlineFlags::AuthorizedToMaintainLiabilities
            | TrustlineFlags::TrustlineClawbackEnabled;
        let op = Operation::new().set_trustline_flags(&account, &asset, set_flags, clear_flags);

        assert_eq!(
            op.err(),
            Some(operation::Error::InvalidField("account".into()))
        );
    }
}
