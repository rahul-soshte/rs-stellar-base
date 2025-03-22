use crate::{
    asset::{Asset, AssetBehavior},
    operation::{self, Operation},
    xdr,
};

impl Operation {
    /// Creates, updates, or deletes an offer to sell a specific amount of an asset for another
    pub fn manage_sell_offer(
        &self,
        selling: &Asset,
        buying: &Asset,
        sell_amount: i64,
        (n, d): (i32, i32),
        offer_id: i64,
    ) -> Result<xdr::Operation, operation::Error> {
        //
        if sell_amount < 0 {
            return Err(operation::Error::InvalidAmount(sell_amount));
        }
        if n <= 0 || d <= 0 {
            return Err(operation::Error::InvalidPrice(n, d));
        }
        let body = xdr::OperationBody::ManageSellOffer(xdr::ManageSellOfferOp {
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

#[cfg(test)]
mod tests {

    use crate::{
        asset::{Asset, AssetBehavior},
        keypair::{Keypair, KeypairBehavior},
        operation::{self, Operation},
        xdr,
    };

    #[test]
    fn test_manage_sell_offer() {
        let selling_issuer = Keypair::random().unwrap().public_key();
        let selling = Asset::new("ABC", Some(&selling_issuer)).unwrap();
        let buying_issuer = Keypair::random().unwrap().public_key();
        let buying = Asset::new("XYZ", Some(&buying_issuer)).unwrap();
        let sell_amount = 38 * operation::ONE;
        let n = 1;
        let d = 2;
        let offer_id = 0;
        let op = Operation::new()
            .manage_sell_offer(&selling, &buying, sell_amount, (n, d), offer_id)
            .unwrap();

        if let xdr::OperationBody::ManageSellOffer(xdr::ManageSellOfferOp {
            selling: s,
            buying: b,
            amount: a,
            price: p,
            offer_id: o,
        }) = op.body
        {
            assert_eq!(s, selling.to_xdr_object());
            assert_eq!(b, buying.to_xdr_object());
            assert_eq!(a, sell_amount);
            assert_eq!(p.n, n);
            assert_eq!(p.d, d);
            assert_eq!(o, offer_id);
        } else {
            panic!("Fail")
        }
    }

    #[test]
    fn test_manage_sell_offer_bad_amount() {
        let selling_issuer = Keypair::random().unwrap().public_key();
        let selling = Asset::new("ABC", Some(&selling_issuer)).unwrap();
        let buying_issuer = Keypair::random().unwrap().public_key();
        let buying = Asset::new("XYZ", Some(&buying_issuer)).unwrap();
        let sell_amount = -38 * operation::ONE;
        let n = 1;
        let d = 2;
        let offer_id = 0;
        let op =
            Operation::new().manage_sell_offer(&selling, &buying, sell_amount, (n, d), offer_id);

        assert_eq!(op.err(), Some(operation::Error::InvalidAmount(sell_amount)));
    }

    #[test]
    fn test_manage_sell_offer_bad_price() {
        let selling_issuer = Keypair::random().unwrap().public_key();
        let selling = Asset::new("ABC", Some(&selling_issuer)).unwrap();
        let buying_issuer = Keypair::random().unwrap().public_key();
        let buying = Asset::new("XYZ", Some(&buying_issuer)).unwrap();
        let sell_amount = 38 * operation::ONE;
        let n = 1;
        let d = 2;
        let offer_id = 0;

        let op =
            Operation::new().manage_sell_offer(&selling, &buying, sell_amount, (-n, d), offer_id);
        assert_eq!(op.err(), Some(operation::Error::InvalidPrice(-n, d)));

        let op =
            Operation::new().manage_sell_offer(&selling, &buying, sell_amount, (-n, -d), offer_id);
        assert_eq!(op.err(), Some(operation::Error::InvalidPrice(-n, -d)));

        let op =
            Operation::new().manage_sell_offer(&selling, &buying, sell_amount, (n, -d), offer_id);
        assert_eq!(op.err(), Some(operation::Error::InvalidPrice(n, -d)));
    }
}
