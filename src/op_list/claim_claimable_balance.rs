use crate::{
    operation::{self, Operation},
    xdr,
};

impl Operation {
    /// Claims a ClaimableBalanceEntry that corresponds to the `balance_id` and adds the amount
    /// of an asset on the entry to the source account
    ///
    /// Threshold: Medium
    pub fn claim_claimable_balance(
        &self,
        balance_id: &str,
    ) -> Result<xdr::Operation, operation::Error> {
        //
        let mut h = [0; 32];
        hex::decode_to_slice(balance_id, &mut h)
            .map_err(|_| operation::Error::InvalidField("balance_id".into()))?;
        let xdr_balance_id = xdr::ClaimableBalanceId::ClaimableBalanceIdTypeV0(xdr::Hash(h));
        let body = xdr::OperationBody::ClaimClaimableBalance(xdr::ClaimClaimableBalanceOp {
            balance_id: xdr_balance_id,
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
        operation::{self, Operation},
        xdr,
    };

    #[test]
    fn test_claim_cb() {
        let balance_id = hex::encode([2; 32]);
        let op = Operation::new()
            .claim_claimable_balance(&balance_id)
            .unwrap();

        if let xdr::OperationBody::ClaimClaimableBalance(xdr::ClaimClaimableBalanceOp {
            balance_id: xdr::ClaimableBalanceId::ClaimableBalanceIdTypeV0(xdr::Hash(h)),
        }) = op.body
        {
            assert_eq!(h, [2; 32]);

            //
        } else {
            panic!("Fail")
        }
    }
    #[test]
    fn test_claim_cb_id_too_big() {
        let balance_id = hex::encode([3; 33]);
        let op = Operation::new().claim_claimable_balance(&balance_id);

        assert_eq!(
            op.err(),
            Some(operation::Error::InvalidField("balance_id".into()))
        );
    }
    #[test]
    fn test_claim_cb_id_too_small() {
        let balance_id = hex::encode([4; 31]);
        let op = Operation::new().claim_claimable_balance(&balance_id);

        assert_eq!(
            op.err(),
            Some(operation::Error::InvalidField("balance_id".into()))
        );
    }
}
