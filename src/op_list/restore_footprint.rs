use crate::{
    operation::{self, Operation},
    xdr,
};

impl Operation {
    /// Make archived Soroban smart contract entries accessible again by restoring them.
    ///
    /// This operation restores the archived entries specified in the `readWrite` footprint.
    ///
    /// Threshold: Medium
    pub fn restore_footprint(&self) -> Result<xdr::Operation, operation::Error> {
        let body = xdr::OperationBody::RestoreFootprint(xdr::RestoreFootprintOp {
            ext: xdr::ExtensionPoint::V0,
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
        let op = Operation::new().restore_footprint().unwrap();

        if let xdr::OperationBody::RestoreFootprint(xdr::RestoreFootprintOp { ext }) = op.body {
            //
        } else {
            panic!("Fail")
        }
    }
}
