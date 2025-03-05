use crate::{
    operation::Operation,
    utils::decode_encode_muxed_account::decode_address_to_muxed_account_fix_for_g_address, xdr,
};

impl Operation {
    /// Transfers the XLM balance of an account to another account and removes the source account
    /// from the ledger
    ///
    /// Threshold: High
    pub fn account_merge(
        destination: String,
        source: Option<String>,
    ) -> Result<xdr::Operation, String> {
        //

        let muxed = match decode_address_to_muxed_account_fix_for_g_address(&destination) {
            account => account,
            _ => return Err("destination is invalid".to_string()),
        };
        let body = xdr::OperationBody::AccountMerge(muxed);
        let source_account = source.map(|s| decode_address_to_muxed_account_fix_for_g_address(&s));
        Ok(xdr::Operation {
            source_account,
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::operation::{self, Operation, OperationBehavior};
    use crate::xdr::{Limits, WriteXdr};

    #[test]
    fn test_account_merge() {
        let destination = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI".into();
        let result = Operation::account_merge(destination, None);
        if let Ok(op) = result {
            let xdr = op.to_xdr(Limits::none()).unwrap();
            let obj = Operation::from_xdr_object(op).unwrap();

            match obj.get("type").unwrap() {
                operation::Value::Single(x) => assert_eq!(x, "accountMerge"),
                _ => panic!("Invalid operation"),
            };
        } else {
            panic!("Fail")
        }
    }
    #[test]
    fn test_account_merge_with_source() {
        let destination = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI".into();
        let source = Some("GAQODVWAY3AYAGEAT4CG3YSPM4FBTBB2QSXCYJLM3HVIV5ILTP5BRXCD".into());
        let result = Operation::account_merge(destination, source);
        if let Ok(op) = result {
            let xdr = op.to_xdr(Limits::none()).unwrap();
            let obj = Operation::from_xdr_object(op).unwrap();

            match obj.get("type").unwrap() {
                operation::Value::Single(x) => assert_eq!(x, "accountMerge"),
                _ => panic!("Invalid operation"),
            };
        } else {
            panic!("Fail")
        }
    }
}
