use crate::{
    operation::{self, Operation},
    xdr,
};

impl Operation {
    /// Creates, updates, or deletes a trustline
    ///
    /// The `asset` can be an [Asset](crate::asset::Asset) or a
    /// [LiquidityPoolAsset](crate::liquidity_pool_asset::LiquidityPoolAsset).
    ///
    /// The `limit` will default to MAX i64 if None. A value of 0 (zero) will remove the trustline.
    ///
    /// Threshold: Medium
    pub fn change_trust(
        &self,
        asset: impl Into<xdr::ChangeTrustAsset>,
        limit: impl Into<Option<i64>>,
    ) -> Result<xdr::Operation, operation::Error> {
        //
        let limit = limit.into().unwrap_or(i64::MAX);
        if limit < 0 {
            return Err(operation::Error::InvalidField("limit".into()));
        }

        let body = xdr::OperationBody::ChangeTrust(xdr::ChangeTrustOp {
            line: asset.into(),
            limit,
        });
        Ok(xdr::Operation {
            source_account: self.source.clone(),
            body,
        })
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        asset::{Asset, AssetBehavior},
        keypair::{Keypair, KeypairBehavior},
        liquidity_pool_asset::{LiquidityPoolAsset, LiquidityPoolAssetBehavior},
        operation::{self, Operation},
        xdr,
    };

    #[test]
    fn test_change_trust_no_limit() {
        let asset_issuer = Keypair::random().unwrap();
        let asset = Asset::new("ABC", Some(&asset_issuer.public_key())).unwrap();
        let op = Operation::new().change_trust(&asset, None).unwrap();

        if let xdr::OperationBody::ChangeTrust(xdr::ChangeTrustOp { line, limit }) = op.body {
            //
            assert_eq!(line, asset.into());
            assert_eq!(limit, i64::MAX);
        } else {
            panic!("Fail")
        }
    }
    #[test]
    fn test_change_trust_no_limit_lp() {
        let a1 = Keypair::random().unwrap().public_key();
        let a2 = Keypair::random().unwrap();
        let asset_a = Asset::new("TEST", Some(&a1)).unwrap();
        let asset_b = Asset::new("ANOTHER", Some(&a1)).unwrap();
        let liq_asset = LiquidityPoolAsset::new(asset_a, asset_b, 30).unwrap();

        let op = Operation::new().change_trust(&liq_asset, None).unwrap();

        if let xdr::OperationBody::ChangeTrust(xdr::ChangeTrustOp { line, limit }) = op.body {
            //
            assert_eq!(line, liq_asset.into());
            assert_eq!(limit, i64::MAX);
        } else {
            panic!("Fail")
        }
    }
    #[test]
    fn test_change_trust_with_limit() {
        let asset_issuer = Keypair::random().unwrap();
        let asset = Asset::new("ABC", Some(&asset_issuer.public_key())).unwrap();
        let op = Operation::new()
            .change_trust(&asset, 200 * operation::ONE)
            .unwrap();

        if let xdr::OperationBody::ChangeTrust(xdr::ChangeTrustOp { line, limit }) = op.body {
            //
            assert_eq!(line, asset.to_change_trust_xdr_object());
            assert_eq!(limit, 200 * operation::ONE);
        } else {
            panic!("Fail")
        }
    }
    #[test]
    fn test_change_trust_remove() {
        let asset_issuer = Keypair::random().unwrap();
        let asset = Asset::new("ABC", Some(&asset_issuer.public_key())).unwrap();
        let op = Operation::new().change_trust(&asset, 0).unwrap();

        if let xdr::OperationBody::ChangeTrust(xdr::ChangeTrustOp { line, limit }) = op.body {
            //
            assert_eq!(line, asset.to_change_trust_xdr_object());
            assert_eq!(limit, 0);
        } else {
            panic!("Fail")
        }
    }
    #[test]
    fn test_change_trust_bad_limit() {
        let asset_issuer = Keypair::random().unwrap();
        let asset = Asset::new("ABC", Some(&asset_issuer.public_key())).unwrap();
        let op = Operation::new().change_trust(&asset, -1);

        assert_eq!(
            op.err(),
            Some(operation::Error::InvalidField("limit".into()))
        );
    }
}
