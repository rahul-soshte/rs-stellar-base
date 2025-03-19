use std::str::FromStr as _;

use crate::operation;
use crate::xdr::PathPaymentStrictReceiveOp;

use crate::asset::AssetBehavior;
use crate::{asset::Asset, operation::Operation, xdr};

impl Operation {
    /// A payment where the asset received can be different from the asset sent; allows the user
    /// to specify the amount of the asset received
    ///
    /// Threshold: Medium
    pub fn path_payment_strict_receive(
        &self,
        send_asset: &Asset,
        send_max: i64,
        destination: &str,
        dest_asset: &Asset,
        dest_amount: i64,
        path: &[&Asset],
    ) -> Result<xdr::Operation, operation::Error> {
        //
        if send_max < 0 {
            return Err(operation::Error::InvalidAmount(send_max));
        }
        if dest_amount < 0 {
            return Err(operation::Error::InvalidAmount(dest_amount));
        }
        let destination = xdr::MuxedAccount::from_str(destination)
            .map_err(|_| operation::Error::InvalidField("destination".into()))?;
        let xdr_path: Vec<xdr::Asset> = path.iter().map(|e| e.to_xdr_object()).collect();
        let path = xdr_path
            .try_into()
            .map_err(|_| operation::Error::InvalidField("path".into()))?;
        let body = xdr::OperationBody::PathPaymentStrictReceive(PathPaymentStrictReceiveOp {
            send_asset: send_asset.to_xdr_object(),
            send_max,
            destination,
            dest_asset: dest_asset.to_xdr_object(),
            dest_amount,
            path,
        });
        Ok(xdr::Operation {
            source_account: self.source.clone(),
            body,
        })
    }
}

#[cfg(test)]
mod tests {
    use stellar_strkey::Strkey;

    use crate::{
        address::{Address, AddressTrait},
        asset::{Asset, AssetBehavior},
        contract::Contracts,
        keypair::{Keypair, KeypairBehavior},
        operation::{self, Operation},
        xdr,
    };

    #[test]
    fn test_path_payment_strict_recv() {
        let send_asset =
            &Asset::new("ABC", Some(&Keypair::random().unwrap().public_key())).unwrap();
        let dest_asset =
            &Asset::new("XYZ", Some(&Keypair::random().unwrap().public_key())).unwrap();
        let path = [
            &Asset::new("DEF", Some(&Keypair::random().unwrap().public_key())).unwrap(),
            &Asset::new("GHI", Some(&Keypair::random().unwrap().public_key())).unwrap(),
            &Asset::new("JKLMNO", Some(&Keypair::random().unwrap().public_key())).unwrap(),
        ];
        let send_amount = 100 * operation::ONE;
        let dest_min = 500 * operation::ONE;
        let destination = &Keypair::random().unwrap().public_key();
        let op = Operation::new()
            .path_payment_strict_receive(
                send_asset,
                send_amount,
                destination,
                dest_asset,
                dest_min,
                &path,
            )
            .unwrap();

        if let xdr::OperationBody::PathPaymentStrictReceive(xdr::PathPaymentStrictReceiveOp {
            send_asset: a_send_asset,
            send_max: a_send_amount,
            destination: a_destination,
            dest_asset: a_dest_asset,
            dest_amount: a_dest_min,
            path: a_path,
        }) = op.body
        {
            //
            assert_eq!(a_send_asset, send_asset.to_xdr_object());
            assert_eq!(a_send_amount, send_amount);
            assert_eq!(a_dest_asset, dest_asset.to_xdr_object());
            assert_eq!(a_path[0], path[0].to_xdr_object());
            assert_eq!(a_path[1], path[1].to_xdr_object());
            assert_eq!(a_path[2], path[2].to_xdr_object());
            assert_eq!(a_dest_min, dest_min);
        }
    }
    #[test]
    fn test_path_payment_strict_recv_bad_destination() {
        let send_asset =
            &Asset::new("ABC", Some(&Keypair::random().unwrap().public_key())).unwrap();
        let dest_asset =
            &Asset::new("XYZ", Some(&Keypair::random().unwrap().public_key())).unwrap();
        let path = [
            &Asset::new("DEF", Some(&Keypair::random().unwrap().public_key())).unwrap(),
            &Asset::new("GHI", Some(&Keypair::random().unwrap().public_key())).unwrap(),
            &Asset::new("JKLMNO", Some(&Keypair::random().unwrap().public_key())).unwrap(),
        ];
        let send_amount = 100 * operation::ONE;
        let dest_min = 500 * operation::ONE;
        let destination = &Keypair::random().unwrap().public_key().replace("G", "C");

        let op = Operation::new().path_payment_strict_receive(
            send_asset,
            send_amount,
            destination,
            dest_asset,
            dest_min,
            &path,
        );

        assert_eq!(
            op.err(),
            Some(operation::Error::InvalidField("destination".into()))
        );
    }
    #[test]
    fn test_path_payment_strict_recv_bad_dest_max() {
        let send_asset =
            &Asset::new("ABC", Some(&Keypair::random().unwrap().public_key())).unwrap();
        let dest_asset =
            &Asset::new("XYZ", Some(&Keypair::random().unwrap().public_key())).unwrap();
        let path = [
            &Asset::new("DEF", Some(&Keypair::random().unwrap().public_key())).unwrap(),
            &Asset::new("GHI", Some(&Keypair::random().unwrap().public_key())).unwrap(),
            &Asset::new("JKLMNO", Some(&Keypair::random().unwrap().public_key())).unwrap(),
        ];
        let send_amount = 100 * operation::ONE;
        let dest_min = 500 * operation::ONE;
        let destination = &Keypair::random().unwrap().public_key();

        let op = Operation::new().path_payment_strict_receive(
            send_asset,
            -send_amount,
            destination,
            dest_asset,
            dest_min,
            &path,
        );

        assert_eq!(
            op.err(),
            Some(operation::Error::InvalidAmount(-send_amount))
        );
    }
    #[test]
    fn test_path_payment_strict_send_bad_dest_amount() {
        let send_asset =
            &Asset::new("ABC", Some(&Keypair::random().unwrap().public_key())).unwrap();
        let dest_asset =
            &Asset::new("XYZ", Some(&Keypair::random().unwrap().public_key())).unwrap();
        let path = [
            &Asset::new("DEF", Some(&Keypair::random().unwrap().public_key())).unwrap(),
            &Asset::new("GHI", Some(&Keypair::random().unwrap().public_key())).unwrap(),
            &Asset::new("JKLMNO", Some(&Keypair::random().unwrap().public_key())).unwrap(),
        ];
        let send_amount = 100 * operation::ONE;
        let dest_min = 500 * operation::ONE;
        let destination = &Keypair::random().unwrap().public_key();

        let op = Operation::new().path_payment_strict_receive(
            send_asset,
            send_amount,
            destination,
            dest_asset,
            -dest_min,
            &path,
        );

        assert_eq!(op.err(), Some(operation::Error::InvalidAmount(-dest_min)));
    }
}
