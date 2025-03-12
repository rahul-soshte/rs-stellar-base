use crate::xdr::CreatePassiveSellOfferOp;

use crate::{
    asset::{Asset, AssetBehavior},
    operation::Operation,
    xdr,
};

impl Operation {
    /// Creates an offer to sell one asset for another without taking a reverse offer of equal price
    pub fn create_passive_sell_offer(
        &self,
        selling: Asset,
        buying: Asset,
        amount: i64,
        (n, d): (i32, i32),
    ) -> Result<xdr::Operation, String> {
        //

        let body = xdr::OperationBody::CreatePassiveSellOffer(CreatePassiveSellOfferOp {
            selling: selling.to_xdr_object(),
            buying: buying.to_xdr_object(),
            amount,
            price: xdr::Price { n, d },
        });
        Ok(xdr::Operation {
            source_account: self.source.clone(),
            body,
        })
    }
}
