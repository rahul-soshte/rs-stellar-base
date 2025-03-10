use crate::{
    asset::{Asset, AssetBehavior},
    operation::Operation,
    utils::decode_encode_muxed_account::decode_address_to_muxed_account_fix_for_g_address,
    xdr,
};

impl Operation {
    pub fn payment(
        &self,
        destination: String,
        asset: &Asset,
        amount: i64,
    ) -> Result<xdr::Operation, String> {
        let destination = match decode_address_to_muxed_account_fix_for_g_address(&destination) {
            account => account,
            _ => return Err("destination is invalid".to_string()),
        };

        let asset: xdr::Asset = asset.to_xdr_object();
        let payment_op = xdr::PaymentOp {
            asset,
            amount,
            destination,
        };

        let body = xdr::OperationBody::Payment(payment_op);

        Ok(xdr::Operation {
            source_account: self.source.clone(),
            body,
        })
    }
}
