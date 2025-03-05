use xdr::BumpSequenceOp;

use crate::{
    operation::Operation,
    utils::decode_encode_muxed_account::decode_address_to_muxed_account_fix_for_g_address, xdr,
};

impl Operation {
    /// Bumps forward the sequence number of the source account to the given sequence number,
    /// invalidating any transaction with a smaller sequence number
    ///
    /// Threshold: Low
    pub fn bump_sequence(sequence: i64, source: Option<String>) -> Result<xdr::Operation, String> {
        if sequence < 0 {
            return Err("invalid sequence".into());
        }
        let body = xdr::OperationBody::BumpSequence(BumpSequenceOp {
            bump_to: xdr::SequenceNumber(sequence),
        });
        let source_account = source.map(|s| decode_address_to_muxed_account_fix_for_g_address(&s));
        Ok(xdr::Operation {
            source_account: None,
            body,
        })
    }
}

#[cfg(test)]
mod tests {

    use crate::{
        operation::{self, Operation, OperationBehavior},
        xdr::{self, WriteXdr},
    };

    #[test]
    fn test_bump_sequence() {
        let source = Some("GAQODVWAY3AYAGEAT4CG3YSPM4FBTBB2QSXCYJLM3HVIV5ILTP5BRXCD".into());
        let op = Operation::bump_sequence(902, source).unwrap();

        dbg!(&op);
        let xdr = op.to_xdr(xdr::Limits::none()).unwrap();
        let obj = Operation::from_xdr_object(op).unwrap();

        match obj.get("type").unwrap() {
            operation::Value::Single(x) => assert_eq!(x, "bumpSequence"),
            _ => panic!("Invalid operation"),
        };
    }
    #[test]
    fn test_bump_sequence_bad() {
        let op = Operation::bump_sequence(-1, None);
        match op {
            Ok(_) => panic!("Failed"),
            Err(e) => assert_eq!(e, "invalid sequence"),
        }
    }
}
