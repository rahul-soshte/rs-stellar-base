use std::str::FromStr;

use crate::{
    asset::{Asset, AssetBehavior},
    operation::{self, Operation},
    xdr,
};

impl Operation {
    /// Allows an account to pay the base reserves for another account; sponsoring account
    /// establishes the is-sponsoring-future-reserves relationship
    ///
    /// There must also be an end sponsoring future reserves operation in the same transaction
    ///
    /// Threshold: Medium
    pub fn begin_sponsoring_future_reserves(
        &self,
        sponsor: &str,
    ) -> Result<xdr::Operation, operation::Error> {
        let sponsored_id = xdr::AccountId::from_str(sponsor)
            .map_err(|_| operation::Error::InvalidField("sponsor".into()))?;
        let begin_sponsorship = xdr::BeginSponsoringFutureReservesOp { sponsored_id };

        let body = xdr::OperationBody::BeginSponsoringFutureReserves(begin_sponsorship);

        Ok(xdr::Operation {
            source_account: self.source.clone(),
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        keypair::{Keypair, KeypairBehavior},
        operation::{self, Operation},
        xdr,
    };

    #[test]
    fn test_begin_sponsorship() {
        let source = Keypair::random().unwrap().public_key();
        let account = Keypair::random().unwrap();
        let op = Operation::with_source(&source)
            .unwrap()
            .begin_sponsoring_future_reserves(&account.public_key())
            .unwrap();

        if let xdr::OperationBody::BeginSponsoringFutureReserves(
            xdr::BeginSponsoringFutureReservesOp {
                sponsored_id: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(pk))),
            },
        ) = op.body
        {
            assert_eq!(&pk.to_vec(), account.raw_public_key());
        } else {
            panic!("Fail")
        }
    }

    #[test]
    fn test_begin_sponsorship_bad_account() {
        let source = Keypair::random().unwrap().public_key();
        let account = Keypair::random().unwrap().public_key().replace("G", "C");
        let op = Operation::with_source(&source)
            .unwrap()
            .begin_sponsoring_future_reserves(&account);

        assert_eq!(
            op.err(),
            Some(operation::Error::InvalidField("sponsor".into()))
        )
    }
}
