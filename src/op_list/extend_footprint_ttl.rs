use crate::{
    operation::{self, Operation},
    xdr,
};

impl Operation {
    /// Extend the time to live (TTL) of entries for Soroban smart contracts.
    ///
    /// This operation extends the TTL of the entries specified in the `readOnly` footprint of
    /// the transaction so that they will live at least until the `extend_to` ledger sequence
    /// number is reached.
    ///
    /// Note that Soroban transactions can only contain one operation per transaction.
    ///
    /// Threshold: Medium
    pub fn extend_footprint_ttl(&self, extend_to: u32) -> Result<xdr::Operation, operation::Error> {
        let body = xdr::OperationBody::ExtendFootprintTtl(xdr::ExtendFootprintTtlOp {
            ext: xdr::ExtensionPoint::V0,
            extend_to,
        });

        Ok(xdr::Operation {
            source_account: self.source.clone(),
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{operation::Operation, xdr};

    fn test_extend_ttl() {
        let op = Operation::new().extend_footprint_ttl(12097).unwrap();

        if let xdr::OperationBody::ExtendFootprintTtl(xdr::ExtendFootprintTtlOp {
            ext,
            extend_to,
        }) = op.body
        {
            assert_eq!(extend_to, 12097);
            //
        } else {
            panic!("Fail")
        }
    }
}
