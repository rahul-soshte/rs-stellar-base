use crate::operation::{is_valid_amount, Operation};
use crate::utils::decode_encode_muxed_account::decode_address_to_muxed_account_fix_for_g_address;
use crate::xdr;
use stellar_strkey::ed25519::PublicKey;
use stellar_strkey::Strkey;

impl Operation {
    /// Creates and funds a new account with the specified starting balance
    /// (the `starting_balance` is in stroops)
    ///
    /// Threshold: Medium
    pub fn create_account(
        destination: String,
        starting_balance: i64,
        source: Option<String>,
    ) -> Result<xdr::Operation, String> {
        if let Strkey::PublicKeyEd25519(PublicKey(pk)) =
            Strkey::from_string(&destination).map_err(|_| "invalid destination")?
        {
            let destination =
                xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(pk)));
            let body = xdr::OperationBody::CreateAccount(xdr::CreateAccountOp {
                destination,
                starting_balance,
            });

            let source_account =
                source.map(|s| decode_address_to_muxed_account_fix_for_g_address(&s));
            Ok(xdr::Operation {
                source_account,
                body,
            })
        } else {
            Err("destination is invalid".into())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::operation::{self, Operation, OperationBehavior};
    use crate::xdr::{Limits, WriteXdr};

    #[test]
    fn test_create_account() {
        let destination = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI".into();
        let result = Operation::create_account(destination, (10 * operation::ONE), None);
        if let Ok(op) = result {
            let xdr = op.to_xdr(Limits::none()).unwrap();
            let obj = Operation::from_xdr_object(op).unwrap();

            match obj.get("type").unwrap() {
                operation::Value::Single(x) => assert_eq!(x, "createAccount"),
                _ => panic!("Invalid operation"),
            };
        } else {
            panic!("Fail")
        }
    }

    #[test]
    fn test_create_account_with_source() {
        let destination = "GBZXN7PIRZGNMHGA7MUUUF4GWPY5AYPV6LY4UV2GL6VJGIQRXFDNMADI".into();
        let source = Some("GAQODVWAY3AYAGEAT4CG3YSPM4FBTBB2QSXCYJLM3HVIV5ILTP5BRXCD".into());
        let result = Operation::create_account(destination, (10 * operation::ONE), source);
        if let Ok(op) = result {
            let xdr = op.to_xdr(Limits::none()).unwrap();
            let obj = Operation::from_xdr_object(op).unwrap();

            match obj.get("type").unwrap() {
                operation::Value::Single(x) => assert_eq!(x, "createAccount"),
                _ => panic!("Invalid operation"),
            };
        } else {
            panic!("Fail")
        }
    }
}
