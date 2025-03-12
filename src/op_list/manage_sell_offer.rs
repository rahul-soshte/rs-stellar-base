use crate::xdr::ManageSellOfferOp;

use crate::{
    asset::{Asset, AssetBehavior},
    operation::Operation,
    xdr,
};

impl Operation {
    /// Creates, updates, or deletes an offer to sell a specific amount of an asset for another
    pub fn manage_sell_offer(
        &self,
        selling: Asset,
        buying: Asset,
        sell_amount: i64,
        (n, d): (i32, i32),
        offer_id: i64,
    ) -> Result<xdr::Operation, String> {
        //

        let body = xdr::OperationBody::ManageSellOffer(ManageSellOfferOp {
            selling: selling.to_xdr_object(),
            buying: buying.to_xdr_object(),
            amount: sell_amount,
            price: xdr::Price { n, d },
            offer_id,
        });
        Ok(xdr::Operation {
            source_account: self.source.clone(),
            body,
        })
    }
}
