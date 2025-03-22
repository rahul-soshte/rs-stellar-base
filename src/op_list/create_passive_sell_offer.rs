use crate::{
    asset::{Asset, AssetBehavior},
    operation::{self, Operation},
    xdr,
};

impl Operation {
    /// Creates an offer to sell one asset for another without taking a reverse offer of equal price
    pub fn create_passive_sell_offer(
        &self,
        selling: &Asset,
        buying: &Asset,
        amount: i64,
        (n, d): (i32, i32),
    ) -> Result<xdr::Operation, operation::Error> {
        //
        if amount < 0 {
            return Err(operation::Error::InvalidAmount(amount));
        }
        if n <= 0 || d <= 0 {
            return Err(operation::Error::InvalidPrice(n, d));
        }
        let body = xdr::OperationBody::CreatePassiveSellOffer(xdr::CreatePassiveSellOfferOp {
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

#[cfg(test)]
mod tests {

    use crate::{
        asset::{Asset, AssetBehavior},
        keypair::{Keypair, KeypairBehavior},
        operation::{self, Operation},
        xdr,
    };

    #[test]
    fn test_create_passive_sell_offer() {
        let selling_issuer = Keypair::random().unwrap().public_key();
        let selling = Asset::new("ABC", Some(&selling_issuer)).unwrap();
        let buying_issuer = Keypair::random().unwrap().public_key();
        let buying = Asset::new("XYZ", Some(&buying_issuer)).unwrap();
        let buy_amount = 38 * operation::ONE;
        let n = 1;
        let d = 2;
        let op = Operation::new()
            .create_passive_sell_offer(&selling, &buying, buy_amount, (n, d))
            .unwrap();

        if let xdr::OperationBody::CreatePassiveSellOffer(xdr::CreatePassiveSellOfferOp {
            selling: s,
            buying: b,
            amount: a,
            price: p,
        }) = op.body
        {
            assert_eq!(s, selling.to_xdr_object());
            assert_eq!(b, buying.to_xdr_object());
            assert_eq!(a, buy_amount);
            assert_eq!(p.n, n);
            assert_eq!(p.d, d);
        } else {
            panic!("Fail")
        }
    }

    #[test]
    fn test_create_passive_sell_offer_bad_amount() {
        let selling_issuer = Keypair::random().unwrap().public_key();
        let selling = Asset::new("ABC", Some(&selling_issuer)).unwrap();
        let buying_issuer = Keypair::random().unwrap().public_key();
        let buying = Asset::new("XYZ", Some(&buying_issuer)).unwrap();
        let buy_amount = 38 * operation::ONE;
        let n = 1;
        let d = 2;
        let op = Operation::new().create_passive_sell_offer(&selling, &buying, -buy_amount, (n, d));

        assert_eq!(op.err(), Some(operation::Error::InvalidAmount(-buy_amount)));
    }

    #[test]
    fn test_create_passive_sell_offer_bad_price() {
        let selling_issuer = Keypair::random().unwrap().public_key();
        let selling = Asset::new("ABC", Some(&selling_issuer)).unwrap();
        let buying_issuer = Keypair::random().unwrap().public_key();
        let buying = Asset::new("XYZ", Some(&buying_issuer)).unwrap();
        let buy_amount = 38 * operation::ONE;
        let n = 1;
        let d = 2;

        let op = Operation::new().create_passive_sell_offer(&selling, &buying, buy_amount, (-n, d));
        assert_eq!(op.err(), Some(operation::Error::InvalidPrice(-n, d)));

        let op =
            Operation::new().create_passive_sell_offer(&selling, &buying, buy_amount, (-n, -d));
        assert_eq!(op.err(), Some(operation::Error::InvalidPrice(-n, -d)));

        let op = Operation::new().create_passive_sell_offer(&selling, &buying, buy_amount, (n, -d));
        assert_eq!(op.err(), Some(operation::Error::InvalidPrice(n, -d)));
    }
}
