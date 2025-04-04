use std::str::FromStr;

use crate::{
    asset::{Asset, AssetBehavior},
    operation::{self, Operation},
    xdr,
};

impl Operation {
    /// Terminates the current is-sponsoring-future-reserves relationship in which the source account is sponsored
    ///
    /// Threshold: Medium
    pub fn end_sponsoring_future_reserves(&self) -> Result<xdr::Operation, operation::Error> {
        let body = xdr::OperationBody::EndSponsoringFutureReserves;

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
        operation::Operation,
    };

    #[test]
    fn test_end_sponsorship() {
        let source = Keypair::random().unwrap().public_key();
        let op = Operation::with_source(&source)
            .unwrap()
            .end_sponsoring_future_reserves();

        assert!(op.is_ok());
    }
}
