use std::str::FromStr;

use stellar_strkey::Strkey;

use crate::{
    asset::{Asset, AssetBehavior},
    operation::{self, Operation},
    xdr,
};

impl Operation {
    pub fn payment(
        &self,
        destination: &str,
        asset: &Asset,
        amount: i64,
    ) -> Result<xdr::Operation, operation::Error> {
        let destination = xdr::MuxedAccount::from_str(destination)
            .map_err(|_| operation::Error::InvalidField("destination".into()))?;
        let asset: xdr::Asset = asset.to_xdr_object();
        let payment_op = xdr::PaymentOp {
            asset,
            amount,
            destination,
        };

        let body = xdr::OperationBody::Payment(payment_op);

        Ok(xdr::Operation {
            source_account: self.source.clone(),
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::contract::ContractBehavior;
    use crate::contract::Contracts;
    use crate::keypair::Keypair;
    use crate::keypair::KeypairBehavior;
    use crate::operation;
    use crate::xdr::WriteXdr;
    use std::convert::TryInto;
    use stellar_strkey::ed25519;
    use stellar_strkey::ed25519::MuxedAccount;
    use stellar_strkey::ed25519::PublicKey;
    use stellar_strkey::Strkey;
    use xdr::ScAddress::Contract;
    use xdr::Uint256;

    use super::*;

    #[test]
    fn test_payment() {
        let dest = &Keypair::random().unwrap().public_key();
        let a = Asset::native();
        let am = operation::ONE;
        let r = Operation::new().payment(dest, &a, am);
        if let Ok(op) = r {
            if let xdr::OperationBody::Payment(xdr::PaymentOp {
                destination,
                asset,
                amount,
            }) = op.body
            {
                if let Strkey::PublicKeyEd25519(PublicKey(pk)) = Strkey::from_string(dest).unwrap()
                {
                    match destination {
                        xdr::MuxedAccount::Ed25519(Uint256(d)) => {
                            assert_eq!(d, pk);
                        }
                        xdr::MuxedAccount::MuxedEd25519(muxed_account_med25519) => {
                            panic!("Not a muxed account")
                        }
                    }
                }
            }
        } else {
            panic!("Fail")
        }
    }

    #[test]
    fn test_payment_muxed() {
        //

        let m = *Keypair::random()
            .unwrap()
            .raw_public_key()
            .last_chunk::<32>()
            .unwrap();
        let dest =
            &Strkey::MuxedAccountEd25519(ed25519::MuxedAccount { ed25519: m, id: 8 }).to_string();
        println!("Dest: {}", dest);
        let a = Asset::native();
        let am = operation::ONE;
        let r = dbg!(Operation::new().payment(dest, &a, am));
        if let Ok(op) = r {
            if let xdr::OperationBody::Payment(xdr::PaymentOp {
                destination,
                asset,
                amount,
            }) = op.body
            {
                if let Strkey::MuxedAccountEd25519(ed25519::MuxedAccount { ed25519, id }) =
                    Strkey::from_string(dest).unwrap()
                {
                    match destination {
                        xdr::MuxedAccount::Ed25519(Uint256(d)) => {
                            panic!("Fail")
                        }
                        xdr::MuxedAccount::MuxedEd25519(muxed_account_med25519) => {
                            assert_eq!(ed25519, muxed_account_med25519.ed25519.0);
                            assert_eq!(id, muxed_account_med25519.id);
                        }
                    }
                } else {
                    panic!("Fail")
                }
            }
        } else {
            panic!("Fail")
        }
    }
}
