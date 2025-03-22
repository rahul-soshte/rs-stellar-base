use crate::{
    asset::{Asset, AssetBehavior},
    operation::{self, Operation},
    xdr,
};

impl Operation {
    /// Creates, updates, or deletes an offer to buy a specific amount of an asset for another
    pub fn manage_buy_offer(
        &self,
        selling: &Asset,
        buying: &Asset,
        buy_amount: i64,
        (n, d): (i32, i32),
        offer_id: i64,
    ) -> Result<xdr::Operation, operation::Error> {
        //
        if buy_amount < 0 {
            return Err(operation::Error::InvalidAmount(buy_amount));
        }
        if n <= 0 || d <= 0 {
            return Err(operation::Error::InvalidPrice(n, d));
        }
        let body = xdr::OperationBody::ManageBuyOffer(xdr::ManageBuyOfferOp {
            selling: selling.to_xdr_object(),
            buying: buying.to_xdr_object(),
            buy_amount,
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
    fn test_manage_buy_offer() {
        let selling_issuer = Keypair::random().unwrap().public_key();
        let selling = Asset::new("ABC", Some(&selling_issuer)).unwrap();
        let buying_issuer = Keypair::random().unwrap().public_key();
        let buying = Asset::new("XYZ", Some(&buying_issuer)).unwrap();
        let buy_amount = 38 * operation::ONE;
        let n = 1;
        let d = 2;
        let offer_id = 0;
        let op = Operation::new()
            .manage_buy_offer(&selling, &buying, buy_amount, (n, d), offer_id)
            .unwrap();

        if let xdr::OperationBody::ManageBuyOffer(xdr::ManageBuyOfferOp {
            selling: s,
            buying: b,
            buy_amount: a,
            price: p,
            offer_id: o,
        }) = op.body
        {
            assert_eq!(s, selling.to_xdr_object());
            assert_eq!(b, buying.to_xdr_object());
            assert_eq!(a, buy_amount);
            assert_eq!(p.n, n);
            assert_eq!(p.d, d);
            assert_eq!(o, offer_id);
        } else {
            panic!("Fail")
        }
    }

    #[test]
    fn test_manage_buy_offer_bad_amount() {
        let selling_issuer = Keypair::random().unwrap().public_key();
        let selling = Asset::new("ABC", Some(&selling_issuer)).unwrap();
        let buying_issuer = Keypair::random().unwrap().public_key();
        let buying = Asset::new("XYZ", Some(&buying_issuer)).unwrap();
        let buy_amount = -38 * operation::ONE;
        let n = 1;
        let d = 2;
        let offer_id = 0;
        let op = Operation::new().manage_buy_offer(&selling, &buying, buy_amount, (n, d), offer_id);
        assert_eq!(op.err(), Some(operation::Error::InvalidAmount(buy_amount)));
    }

    #[test]
    fn test_manage_buy_offer_bad_price() {
        let selling_issuer = Keypair::random().unwrap().public_key();
        let selling = Asset::new("ABC", Some(&selling_issuer)).unwrap();
        let buying_issuer = Keypair::random().unwrap().public_key();
        let buying = Asset::new("XYZ", Some(&buying_issuer)).unwrap();
        let buy_amount = 38 * operation::ONE;
        let n = 1;
        let d = 2;
        let offer_id = 0;

        let op =
            Operation::new().manage_buy_offer(&selling, &buying, buy_amount, (-n, d), offer_id);
        assert_eq!(op.err(), Some(operation::Error::InvalidPrice(-n, d)));

        let op =
            Operation::new().manage_buy_offer(&selling, &buying, buy_amount, (-n, -d), offer_id);
        assert_eq!(op.err(), Some(operation::Error::InvalidPrice(-n, -d)));

        let op =
            Operation::new().manage_buy_offer(&selling, &buying, buy_amount, (n, -d), offer_id);
        assert_eq!(op.err(), Some(operation::Error::InvalidPrice(n, -d)));
    }
}
