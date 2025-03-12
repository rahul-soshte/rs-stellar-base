use crate::xdr::PathPaymentStrictSendOp;

use crate::asset::AssetBehavior;
use crate::operation::OperationBehavior;
use crate::utils::decode_encode_muxed_account::decode_address_to_muxed_account_fix_for_g_address;
use crate::{asset::Asset, operation::Operation, xdr};

impl Operation {
    /// A payment where the asset sent can be different than the asset received; allows the user
    /// to specify the amount of the asset to send
    ///
    /// Threshold: Medium
    pub fn path_payment_strict_send(
        &self,
        send_asset: Asset,
        send_amount: i64,
        destination: String,
        dest_asset: Asset,
        dest_min: i64,
        path: Vec<Asset>,
    ) -> Result<xdr::Operation, String> {
        //
        let destination = decode_address_to_muxed_account_fix_for_g_address(&destination);
        let xdr_path: Vec<xdr::Asset> = path.iter().map(|e| e.to_xdr_object()).collect();
        let path = xdr_path.try_into().map_err(|_| "invalid path")?;
        let body = xdr::OperationBody::PathPaymentStrictSend(PathPaymentStrictSendOp {
            send_asset: send_asset.to_xdr_object(),
            send_amount,
            destination,
            dest_asset: dest_asset.to_xdr_object(),
            dest_min,
            path,
        });
        Ok(xdr::Operation {
            source_account: self.source.clone(),
            body,
        })
    }
}
