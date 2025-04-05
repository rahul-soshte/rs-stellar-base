use crate::{
    asset::{Asset, AssetBehavior},
    claimant::{Claimant, ClaimantBehavior},
    operation::{self, Operation},
    xdr,
};

impl Operation {
    /// Moves an amount of asset from the operation source account into a new ClaimableBalanceEntry
    ///
    /// Threshold: Medium
    pub fn create_claimable_balance(
        &self,
        asset: &Asset,
        amount: i64,
        claimants: Vec<Claimant>,
    ) -> Result<xdr::Operation, operation::Error> {
        //
        if amount < 0 {
            return Err(operation::Error::InvalidAmount(amount));
        }
        let xdr_claimants: Vec<xdr::Claimant> =
            claimants.iter().map(|c| c.to_xdr_object()).collect();
        let body = xdr::OperationBody::CreateClaimableBalance(xdr::CreateClaimableBalanceOp {
            asset: asset.to_xdr_object(),
            amount,
            claimants: xdr_claimants
                .try_into()
                .map_err(|_| operation::Error::InvalidField("claimants".into()))?,
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
        claimant::{Claimant, ClaimantBehavior},
        keypair::{Keypair, KeypairBehavior},
        operation::{self, Operation},
        xdr,
    };

    #[test]
    fn test_create_cb() {
        let asset = Asset::native();
        let amount = 100 * operation::ONE;
        let account = Keypair::random().unwrap();
        let claimants = vec![Claimant::new(Some(&account.public_key()), None).unwrap()];
        let op = Operation::new()
            .create_claimable_balance(&asset, amount, claimants)
            .unwrap();

        if let xdr::OperationBody::CreateClaimableBalance(xdr::CreateClaimableBalanceOp {
            asset: xdr_asset,
            amount: xdr_amount,
            claimants: xdr_claimants,
        }) = op.body
        {
            assert_eq!(xdr_asset, asset.to_xdr_object());
            assert_eq!(xdr_amount, amount);
            let xdr::Claimant::ClaimantTypeV0(xdr::ClaimantV0 {
                destination: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(pk))),
                predicate,
            }) = &xdr_claimants[0];
            assert_eq!(pk, &account.raw_pubkey());
            assert_eq!(predicate, &xdr::ClaimPredicate::Unconditional);
        } else {
            panic!("Fail")
        }
    }

    #[test]
    fn test_create_cb_bad_amount() {
        let asset = Asset::native();
        let amount = 100 * operation::ONE;
        let account = Keypair::random().unwrap();
        let claimants = vec![Claimant::new(Some(&account.public_key()), None).unwrap()];
        let op = Operation::new().create_claimable_balance(&asset, -amount, claimants);

        assert_eq!(op.err(), Some(operation::Error::InvalidAmount(-amount)));
    }
}
