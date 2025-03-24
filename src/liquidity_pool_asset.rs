use crate::asset::Asset;
use crate::asset::AssetBehavior;
use crate::get_liquidity_pool::LiquidityPool;
use crate::get_liquidity_pool::LiquidityPoolBehavior;
use crate::xdr;
const LIQUIDITY_POOL_FEE_V18: i32 = 30;
#[derive(Debug)]
pub struct LiquidityPoolAsset {
    asset_a: Asset,
    asset_b: Asset,
    fee: i32,
}

// TODO: fix that
impl From<&LiquidityPoolAsset> for xdr::TrustLineAsset {
    fn from(value: &LiquidityPoolAsset) -> Self {
        let pool_id = LiquidityPool::get_liquidity_pool_id(
            "constant_product",
            value.get_liquidity_pool_parameters().clone(),
        )
        .unwrap();
        xdr::TrustLineAsset::PoolShare(xdr::PoolId(xdr::Hash(*pool_id.last_chunk::<32>().unwrap())))
    }
}
// TODO: fix that
impl From<LiquidityPoolAsset> for xdr::TrustLineAsset {
    fn from(value: LiquidityPoolAsset) -> Self {
        let pool_id = LiquidityPool::get_liquidity_pool_id(
            "constant_product",
            value.get_liquidity_pool_parameters().clone(),
        )
        .unwrap();
        xdr::TrustLineAsset::PoolShare(xdr::PoolId(xdr::Hash(*pool_id.last_chunk::<32>().unwrap())))
    }
}

// Define a trait for LiquidityPoolAsset behavior
pub trait LiquidityPoolAssetBehavior {
    fn new(asset_a: Asset, asset_b: Asset, fee: i32) -> Result<Self, &'static str>
    where
        Self: Sized;
    fn from_operation(ct_asset_xdr: &xdr::ChangeTrustAsset) -> Result<Self, String>
    where
        Self: Sized;
    fn to_xdr_object(&self) -> xdr::ChangeTrustAsset;
    fn get_liquidity_pool_parameters(&self) -> xdr::LiquidityPoolParameters;
    fn equals(&self, other: &Self) -> bool;
    fn get_asset_type(&self) -> &'static str;
    fn to_string(&self) -> String;
}

impl LiquidityPoolAssetBehavior for LiquidityPoolAsset {
    fn new(asset_a: Asset, asset_b: Asset, fee: i32) -> Result<Self, &'static str> {
        if Asset::compare(&asset_a, &asset_b) != -1 {
            return Err("Assets are not in lexicographic order");
        }
        if fee != LIQUIDITY_POOL_FEE_V18 {
            return Err("fee is invalid");
        }

        Ok(LiquidityPoolAsset {
            asset_a,
            asset_b,
            fee,
        })
    }

    fn from_operation(ct_asset_xdr: &xdr::ChangeTrustAsset) -> Result<LiquidityPoolAsset, String> {
        match ct_asset_xdr {
            xdr::ChangeTrustAsset::PoolShare(x) => {
                let xdr::LiquidityPoolParameters::LiquidityPoolConstantProduct(val) = x;

                let asset_a = Asset::from_operation(val.asset_a.clone()).unwrap();
                let asset_b = Asset::from_operation(val.asset_b.clone()).unwrap();
                let fee = val.fee;
                Ok(LiquidityPoolAsset::new(asset_a, asset_b, fee)?)
            }

            _ => Err("Invalid asset type".to_string()),
        }
    }

    fn to_xdr_object(&self) -> xdr::ChangeTrustAsset {
        let lp_constant_product_params_xdr = xdr::LiquidityPoolConstantProductParameters {
            asset_a: self.asset_a.to_xdr_object(),
            asset_b: self.asset_b.to_xdr_object(),
            fee: self.fee,
        };

        let lp_params_xdr = xdr::LiquidityPoolParameters::LiquidityPoolConstantProduct(
            lp_constant_product_params_xdr,
        );
        xdr::ChangeTrustAsset::PoolShare(lp_params_xdr)
    }

    fn get_liquidity_pool_parameters(&self) -> xdr::LiquidityPoolParameters {
        let lp_constant_product_params_xdr = xdr::LiquidityPoolConstantProductParameters {
            asset_a: self.asset_a.to_xdr_object(),
            asset_b: self.asset_b.to_xdr_object(),
            fee: self.fee,
        };

        xdr::LiquidityPoolParameters::LiquidityPoolConstantProduct(lp_constant_product_params_xdr)
    }

    fn equals(&self, other: &LiquidityPoolAsset) -> bool {
        self.asset_a == other.asset_a && self.asset_b == other.asset_b && self.fee == other.fee
    }

    fn get_asset_type(&self) -> &'static str {
        "liquidity_pool_shares"
    }

    fn to_string(&self) -> String {
        let pool_id = LiquidityPool::get_liquidity_pool_id(
            "constant_product",
            self.get_liquidity_pool_parameters().clone(),
        )
        .unwrap();
        format!("liquidity_pool:{}", hex::encode(pool_id))
    }
}

#[cfg(test)]
mod tests {
    use xdr::AlphaNum4;

    use super::*;

    #[test]
    fn correct_attributes_does_not_panic() {
        const LIQUIDITY_POOL_FEE_V18: i32 = 30;
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
        let fee = LIQUIDITY_POOL_FEE_V18;

        let _ = LiquidityPoolAsset::new(asset_a, asset_b, fee);
    }

    #[test]
    fn returns_liquidity_pool_parameters_for_liquidity_pool_asset() {
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
        let fee = LIQUIDITY_POOL_FEE_V18;

        let asset = LiquidityPoolAsset::new(asset_a.clone(), asset_b.clone(), fee).unwrap();

        let got_pool_params = asset.get_liquidity_pool_parameters();
        let val = match got_pool_params {
            xdr::LiquidityPoolParameters::LiquidityPoolConstantProduct(x) => x,
        };
        assert_eq!(val.asset_a, asset_a.to_xdr_object());
        assert_eq!(val.asset_b, asset_b.to_xdr_object());
        assert_eq!(val.fee, fee);
    }

    #[test]
    fn returns_liquidity_pool_shares_for_trustline_asset() {
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
        let fee = LIQUIDITY_POOL_FEE_V18;

        let asset = LiquidityPoolAsset::new(asset_a, asset_b, fee).unwrap();

        assert_eq!(asset.get_asset_type(), "liquidity_pool_shares");
    }

    #[test]
    fn to_xdr_object_parses_liquidity_pool_trustline_asset_object() {
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
        let fee = LIQUIDITY_POOL_FEE_V18;
        let asset = LiquidityPoolAsset::new(asset_a.clone(), asset_b.clone(), fee).unwrap();
        let xdr = asset.to_xdr_object();

        let val = match xdr {
            xdr::ChangeTrustAsset::PoolShare(x) => x,
            _ => panic!("Expected LiquidityPool variant"),
        };

        let got_pool_params: xdr::LiquidityPoolParameters = asset.get_liquidity_pool_parameters();
        let val = match got_pool_params {
            xdr::LiquidityPoolParameters::LiquidityPoolConstantProduct(x) => x,
        };
        assert_eq!(Asset::from_operation(val.asset_a).unwrap(), asset_a);
        assert_eq!(Asset::from_operation(val.asset_b).unwrap(), asset_b);
        assert_eq!(val.fee, fee);
    }

    #[test]
    fn from_operation_throws_error_for_native_asset_type() {
        let xdr = xdr::ChangeTrustAsset::Native;

        let result = LiquidityPoolAsset::from_operation(&xdr).unwrap_err();

        let val = "Invalid asset type".to_string();

        if val == result {
            ()
        } else {
            panic!("Expected error with message containing 'Invalid asset type: assetTypeNative'")
        }
    }

    #[test]
    fn test_invalid_asset_type_credit_alphanum4() {
        let issuer = "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ";
        let asset_code = "KHL";

        let asset_xdr = Asset::new("KHL", Some(issuer)).unwrap().to_xdr_object();
        let c = match asset_xdr {
            xdr::Asset::CreditAlphanum4(x) => x,
            _ => panic!("Wrong Type:"),
        };

        let vval: xdr::ChangeTrustAsset = xdr::ChangeTrustAsset::CreditAlphanum4(c);

        match LiquidityPoolAsset::from_operation(&vval) {
            Ok(_) => panic!("Expected an error for assetTypeCreditAlphanum4, but got Ok"),
            Err(e) => assert_eq!(e.to_string(), "Invalid asset type"),
        }
    }

    #[test]
    fn test_invalid_asset_type_credit_alphanum12() {
        let issuer = "GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ";
        let asset_code = "KHLTOKEN";

        let asset_xdr = Asset::new(asset_code, Some(issuer))
            .unwrap()
            .to_xdr_object();
        let c = match asset_xdr {
            xdr::Asset::CreditAlphanum12(x) => x,
            _ => panic!("Wrong Type:"),
        };

        let vval: xdr::ChangeTrustAsset = xdr::ChangeTrustAsset::CreditAlphanum12(c);

        match LiquidityPoolAsset::from_operation(&vval) {
            Ok(_) => panic!("Expected an error for assetTypeCreditAlphanum12, but got Ok"),
            Err(e) => assert_eq!(e.to_string(), "Invalid asset type"),
        }
    }

    #[test]
    fn test_parses_liquidity_pool_asset_xdr() {
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
        let fee = LIQUIDITY_POOL_FEE_V18;

        let lp_constant_product_params_xdr = xdr::LiquidityPoolConstantProductParameters {
            asset_a: asset_a.to_xdr_object(),
            asset_b: asset_b.to_xdr_object(),
            fee,
        };

        let lp_params_xdr = xdr::LiquidityPoolParameters::LiquidityPoolConstantProduct(
            lp_constant_product_params_xdr,
        );
        let xdr = xdr::ChangeTrustAsset::PoolShare(lp_params_xdr);

        let asset = LiquidityPoolAsset::from_operation(&xdr).expect("Expected successful parsing");
        let got_pool_params = asset.get_liquidity_pool_parameters();
        let x = match got_pool_params {
            xdr::LiquidityPoolParameters::LiquidityPoolConstantProduct(x) => x,
        };
        assert_eq!(x.asset_a, asset_a.to_xdr_object());
        assert_eq!(x.asset_b, asset_b.to_xdr_object());
        assert_eq!(x.fee, fee);
    }

    #[test]
    fn test_assets_are_different() {
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
        let fee = LIQUIDITY_POOL_FEE_V18;

        let lp_asset1 = LiquidityPoolAsset::new(asset_a.clone(), asset_b.clone(), fee).unwrap();

        let asset_a2 = Asset::new(
            "ARS2",
            Some("GB7TAYRUZGE6TVT7NHP5SMIZRNQA6PLM423EYISAOAP3MKYIQMVYP2JO"),
        )
        .unwrap();
        let asset_b2 = Asset::new(
            "USD2",
            Some("GCEZWKCA5VLDNRLN3RPRJMRZOX3Z6G5CHCGSNFHEYVXM3XOJMDS674JZ"),
        )
        .unwrap();

        let mut lp_asset2 =
            LiquidityPoolAsset::new(asset_a2, asset_b2.clone(), LIQUIDITY_POOL_FEE_V18).unwrap();
        assert!(!lp_asset1.equals(&lp_asset2));

        lp_asset2 = LiquidityPoolAsset::new(asset_a, asset_b2, fee).unwrap();
        assert!(!lp_asset1.equals(&lp_asset2));
    }

    #[test]
    fn test_to_string() {
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
        let fee = LIQUIDITY_POOL_FEE_V18;

        let asset = LiquidityPoolAsset::new(asset_a, asset_b, fee).unwrap();
        assert_eq!(
            asset.to_string(),
            "liquidity_pool:dd7b1ab831c273310ddbec6f97870aa83c2fbd78ce22aded37ecbf4f3380fac7"
        );
    }
}
