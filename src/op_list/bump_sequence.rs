use crate::{
    operation::{self, Operation},
    xdr,
};

impl Operation {
    /// Bumps forward the sequence number of the source account to the given sequence number,
    /// invalidating any transaction with a smaller sequence number
    ///
    /// Threshold: Low
    pub fn bump_sequence(&self, sequence: i64) -> Result<xdr::Operation, operation::Error> {
        if sequence < 0 {
            return Err(operation::Error::InvalidField("sequence".into()));
        }

        let bump_to = xdr::SequenceNumber(sequence);
        let body = xdr::OperationBody::BumpSequence(xdr::BumpSequenceOp { bump_to });

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
        xdr::{self, WriteXdr},
    };

    #[test]
    fn test_bump_sequence() {
        let source = "GAQODVWAY3AYAGEAT4CG3YSPM4FBTBB2QSXCYJLM3HVIV5ILTP5BRXCD";
        let op = Operation::with_source(source)
            .unwrap()
            .bump_sequence(902)
            .unwrap();
    }
    #[test]
    fn test_bump_sequence_bad() {
        let op = Operation::new().bump_sequence(-1);

        assert_eq!(
            op.err(),
            Some(operation::Error::InvalidField("sequence".into()))
        );
    }
}
