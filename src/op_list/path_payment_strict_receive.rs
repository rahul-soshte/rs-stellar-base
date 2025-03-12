use crate::xdr::PathPaymentStrictReceiveOp;

use crate::asset::AssetBehavior;
use crate::operation::OperationBehavior;
use crate::utils::decode_encode_muxed_account::decode_address_to_muxed_account_fix_for_g_address;
use crate::{asset::Asset, operation::Operation, xdr};

impl Operation {
    /// A payment where the asset received can be different from the asset sent; allows the user
    /// to specify the amount of the asset received
    ///
    /// Threshold: Medium
    pub fn path_payment_strict_receive(
        &self,
        send_asset: Asset,
        send_max: i64,
        destination: String,
        dest_asset: Asset,
        dest_amount: i64,
        path: Vec<Asset>,
    ) -> Result<xdr::Operation, String> {
        //
        let destination = decode_address_to_muxed_account_fix_for_g_address(&destination);
        let xdr_path: Vec<xdr::Asset> = path.iter().map(|e| e.to_xdr_object()).collect();
        let path = xdr_path.try_into().map_err(|_| "invalid path")?;
        let body = xdr::OperationBody::PathPaymentStrictReceive(PathPaymentStrictReceiveOp {
            send_asset: send_asset.to_xdr_object(),
            send_max,
            destination,
            dest_asset: dest_asset.to_xdr_object(),
            dest_amount,
            path,
        });
        Ok(xdr::Operation {
            source_account: self.source.clone(),
            body,
        })
    }
}
