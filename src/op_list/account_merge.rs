use std::str::FromStr;

use crate::{
    operation::{self, Operation},
    xdr,
};

impl Operation {
    /// Transfers the XLM balance of an account to another account and removes the source account
    /// from the ledger
    ///
    /// Threshold: High
    pub fn account_merge(&self, destination: &str) -> Result<xdr::Operation, operation::Error> {
        //
        let muxed = xdr::MuxedAccount::from_str(destination)
            .map_err(|_| operation::Error::InvalidField("destination".into()))?;
        let body = xdr::OperationBody::AccountMerge(muxed);
        Ok(xdr::Operation {
            source_account: self.source.clone(),
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use stellar_strkey::{ed25519, Strkey};

    use crate::operation::{self, Operation};
    use crate::xdr::{self, Limits, WriteXdr};

    #[test]
    fn test_account_merge() {
        let destination = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
        let result = Operation::new().account_merge(destination);
        if let Ok(op) = result {
            if let xdr::OperationBody::AccountMerge(xdr::MuxedAccount::Ed25519(xdr::Uint256(mpk))) =
                op.body
            {
                if let Strkey::PublicKeyEd25519(ed25519::PublicKey(pk)) =
                    Strkey::from_str(destination).unwrap()
                {
                    assert_eq!(mpk, pk);
                    return;
                }
            }
        }
        panic!("Fail")
    }
    #[test]
    fn test_account_merge_with_source() {
        let destination = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI";
        let source = "GAQODVWAY3AYAGEAT4CG3YSPM4FBTBB2QSXCYJLM3HVIV5ILTP5BRXCD";
        let result = Operation::with_source(source)
            .unwrap()
            .account_merge(destination);

        if let Ok(op) = result {
            if let xdr::OperationBody::AccountMerge(xdr::MuxedAccount::Ed25519(xdr::Uint256(mpk))) =
                op.body
            {
                if let Strkey::PublicKeyEd25519(ed25519::PublicKey(pk)) =
                    Strkey::from_str(destination).unwrap()
                {
                    assert_eq!(mpk, pk);
                    assert_eq!(
                        op.source_account,
                        Some(xdr::MuxedAccount::from_str(source).unwrap())
                    );
                    return;
                }
            }
        }
        panic!("Fail")
    }

    #[test]
    fn test_account_merge_bad_destination() {
        let dest = &Strkey::Contract(stellar_strkey::Contract([0; 32])).to_string();
        let r = Operation::new().account_merge(dest);

        assert_eq!(
            r.err().unwrap(),
            operation::Error::InvalidField("destination".into())
        );
    }
}
