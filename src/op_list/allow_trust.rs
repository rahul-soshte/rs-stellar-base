use stellar_strkey::Strkey;

use crate::{
    address::{Address, AddressTrait},
    asset::Asset,
    operation::Operation,
    utils::decode_encode_muxed_account::decode_address_to_muxed_account_fix_for_g_address,
    xdr::{self, AllowTrustOp, AlphaNum4, AssetCode12, AssetCode4, PublicKey},
};

impl Operation {
    /// Updates the authorized flag of an existing trustline. This can only be called by the issuer
    /// of a trustline's asset. The issuer can only clear the authorized flag if the issuer has
    /// the AUTH_REVOCABLE_FLAG set. Otherwise, the issuer can only set the authorized flag.
    ///
    ///Threshold: Low
    pub fn allow_trust(
        trustor: String,
        asset_code: String,
        authorize: bool,
        source: Option<String>,
    ) -> Result<xdr::Operation, String> {
        let t = Strkey::from_string(&trustor).map_err(|_| "trustor is invalid")?;

        if let Strkey::PublicKeyEd25519(account_id) = t {
            let asset = match asset_code.clone() {
                x if x.len() <= 4 => {
                    let mut code = [0; 4];
                    let b = asset_code.as_bytes();
                    code[..b.len()].copy_from_slice(b);
                    xdr::AssetCode::CreditAlphanum4(AssetCode4(code))
                }
                x if x.len() <= 12 => {
                    let mut code = [0; 12];
                    let b = asset_code.as_bytes();
                    code[..b.len()].copy_from_slice(b);
                    xdr::AssetCode::CreditAlphanum12(AssetCode12(code))
                }
                _ => return Err("asset_code is invalid".into()),
            };
            let authorize_flag = if authorize {
                xdr::TrustLineFlags::AuthorizedFlag.into()
            } else {
                0
            };
            let body = xdr::OperationBody::AllowTrust(AllowTrustOp {
                trustor: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(
                    account_id.0,
                ))),
                asset,
                authorize: authorize_flag as u32,
            });
            let source_account =
                source.map(|s| decode_address_to_muxed_account_fix_for_g_address(&s));
            Ok(xdr::Operation {
                body,
                source_account,
            })
        } else {
            Err("trustor is invalid".into())
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        operation::{self, Operation, OperationBehavior},
        xdr::{self, WriteXdr},
    };

    #[test]
    fn test_allow_trust_true() {
        let trustor = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI".into();
        let asset_code = "SORO".into();
        let authorize = true;
        let op = Operation::allow_trust(trustor, asset_code, authorize, None).unwrap();

        dbg!(&op);
        let xdr = op.to_xdr(xdr::Limits::none()).unwrap();
        let obj = Operation::from_xdr_object(op).unwrap();

        match obj.get("type").unwrap() {
            operation::Value::Single(x) => assert_eq!(x, "allowTrust"),
            _ => panic!("Invalid operation"),
        };
    }
    #[test]
    fn test_allow_trust_false() {
        let trustor = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI".into();
        let source = Some("GAQODVWAY3AYAGEAT4CG3YSPM4FBTBB2QSXCYJLM3HVIV5ILTP5BRXCD".into());
        let asset_code = "SOROBAN".into();
        let authorize = true;
        let op = Operation::allow_trust(trustor, asset_code, authorize, source).unwrap();

        dbg!(&op);
        let xdr = op.to_xdr(xdr::Limits::none()).unwrap();
        let obj = Operation::from_xdr_object(op).unwrap();

        match obj.get("type").unwrap() {
            operation::Value::Single(x) => assert_eq!(x, "allowTrust"),
            _ => panic!("Invalid operation"),
        };
    }
}
