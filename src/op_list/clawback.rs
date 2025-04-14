use std::str::FromStr;

use crate::{
    asset::{Asset, AssetBehavior},
    operation::{self, Operation},
    xdr,
};

impl Operation {
    /// Burns an amount in a specific asset from an account. Only the issuing account for the
    /// asset can perform this operation.
    ///
    /// Threshold: Medium
    pub fn clawback(
        &self,
        asset: &Asset,
        amount: i64,
        from: &str,
    ) -> Result<xdr::Operation, operation::Error> {
        //
        let asset: xdr::Asset = asset.to_xdr_object();
        if amount < 0 {
            return Err(operation::Error::InvalidAmount(amount));
        }
        let from = xdr::MuxedAccount::from_str(from)
            .map_err(|_| operation::Error::InvalidField("from".into()))?;
        let body = xdr::OperationBody::Clawback(xdr::ClawbackOp {
            asset,
            from,
            amount,
        });
        Ok(xdr::Operation {
            source_account: self.source.clone(),
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use stellar_strkey::{ed25519, Strkey};

    use crate::{
        asset::{Asset, AssetBehavior},
        keypair::{Keypair, KeypairBehavior},
        operation::{self, Operation},
        xdr,
    };

    #[test]
    fn test_clawback() {
        let asset_issuer = Keypair::random().unwrap().public_key();
        let asset = Asset::new("ABC", Some(&asset_issuer)).unwrap();
        let amount = 100 * operation::ONE;
        let from = Keypair::random().unwrap();
        let op = Operation::new()
            .clawback(&asset, amount, &from.public_key())
            .unwrap();

        if let xdr::OperationBody::Clawback(xdr::ClawbackOp {
            asset: a,
            from: xdr::MuxedAccount::Ed25519(xdr::Uint256(pk)),
            amount: am,
        }) = op.body
        {
            //
            assert_eq!(a, asset.to_xdr_object());
            assert_eq!(pk, from.raw_pubkey());
            assert_eq!(am, amount);
        } else {
            panic!("Fail")
        }
    }
    #[test]
    fn test_clawback_muxed() {
        let asset_issuer = Keypair::random().unwrap().public_key();
        let asset = Asset::new("ABC", Some(&asset_issuer)).unwrap();
        let amount = 100 * operation::ONE;
        let m = *Keypair::random()
            .unwrap()
            .raw_public_key()
            .last_chunk::<32>()
            .unwrap();
        let from =
            Strkey::MuxedAccountEd25519(ed25519::MuxedAccount { ed25519: m, id: 8 }).to_string();
        let op = Operation::new().clawback(&asset, amount, &from).unwrap();

        if let xdr::OperationBody::Clawback(xdr::ClawbackOp {
            asset: a,
            from:
                xdr::MuxedAccount::MuxedEd25519(xdr::MuxedAccountMed25519 {
                    id,
                    ed25519: xdr::Uint256(pk),
                }),
            amount: am,
        }) = op.body
        {
            //
            assert_eq!(a, asset.to_xdr_object());
            assert_eq!(pk, m);
            assert_eq!(id, 8);
            assert_eq!(am, amount);
        } else {
            panic!("Fail")
        }
    }
    #[test]
    fn test_clawback_bad_amount() {
        let asset_issuer = Keypair::random().unwrap().public_key();
        let asset = Asset::new("ABC", Some(&asset_issuer)).unwrap();
        let amount = 100 * operation::ONE;
        let from = Keypair::random().unwrap();
        let op = Operation::new().clawback(&asset, -amount, &from.public_key());

        assert_eq!(op.err(), Some(operation::Error::InvalidAmount(-amount)));
    }
    #[test]
    fn test_clawback_bad_account() {
        let asset_issuer = Keypair::random().unwrap().public_key();
        let asset = Asset::new("ABC", Some(&asset_issuer)).unwrap();
        let amount = 100 * operation::ONE;
        let from = Strkey::Contract(stellar_strkey::Contract([0; 32])).to_string();

        let op = Operation::new().clawback(&asset, amount, &from);

        assert_eq!(
            op.err(),
            Some(operation::Error::InvalidField("from".into()))
        );
    }
}
