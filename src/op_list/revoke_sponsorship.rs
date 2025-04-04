use std::str::FromStr;

use stellar_strkey::Strkey;

use crate::{
    asset::{Asset, AssetBehavior},
    operation::{self, Operation},
    xdr,
};

impl Operation {
    /// Revoke sponsorship for the `signer` on the `account`
    ///
    /// The `signer` is the Strkey representation of:
    /// - An Ed25529 public key
    /// - An Ed25519SignedPayload
    /// - A PreAuthTx
    /// - A HashX
    ///
    /// Threshold: Medium
    pub fn revoke_signer_sponsorship(
        &self,
        account: &str,
        signer: &str,
    ) -> Result<xdr::Operation, operation::Error> {
        let account_id = xdr::AccountId::from_str(account)
            .map_err(|_| operation::Error::InvalidField("account".into()))?;
        let signer_key = match Strkey::from_string(signer)
            .map_err(|_| operation::Error::InvalidField("signer".into()))?
        {
            Strkey::PublicKeyEd25519(stellar_strkey::ed25519::PublicKey(key)) => {
                xdr::SignerKey::Ed25519(xdr::Uint256(key))
            }
            Strkey::PreAuthTx(stellar_strkey::PreAuthTx(key)) => {
                xdr::SignerKey::PreAuthTx(xdr::Uint256(key))
            }
            Strkey::HashX(stellar_strkey::HashX(key)) => xdr::SignerKey::HashX(xdr::Uint256(key)),
            Strkey::SignedPayloadEd25519(stellar_strkey::ed25519::SignedPayload {
                ed25519,
                payload,
            }) => xdr::SignerKey::Ed25519SignedPayload(xdr::SignerKeyEd25519SignedPayload {
                ed25519: xdr::Uint256(ed25519),
                payload: payload
                    .try_into()
                    .map_err(|_| operation::Error::InvalidField("signer".into()))?,
            }),
            _ => return Err(operation::Error::InvalidField("signer".into())),
        };

        let body = xdr::OperationBody::RevokeSponsorship(xdr::RevokeSponsorshipOp::Signer(
            xdr::RevokeSponsorshipOpSigner {
                account_id,
                signer_key,
            },
        ));

        Ok(xdr::Operation {
            source_account: self.source.clone(),
            body,
        })
    }

    /// Revoke sponsorship for the `account`
    ///
    /// Threshold: Medium
    pub fn revoke_account_sponsorship(
        &self,
        account: &str,
    ) -> Result<xdr::Operation, operation::Error> {
        let account_id = xdr::AccountId::from_str(account)
            .map_err(|_| operation::Error::InvalidField("account".into()))?;
        let key = xdr::LedgerKey::Account(xdr::LedgerKeyAccount { account_id });
        self.revoke_ledger_key_sponsorship(key)
    }

    /// Revoke sponsorship for the `trustline` on the `account`
    ///
    /// The `trustline` can be:
    /// - an [Asset]
    /// - a [LiquidityPoolAsset](crate::liquidity_pool_asset::LiquidityPoolAsset)
    ///
    /// Threshold: Medium
    pub fn revoke_trustline_sponsorship(
        &self,
        account: &str,
        trustline: impl Into<xdr::TrustLineAsset>,
    ) -> Result<xdr::Operation, operation::Error> {
        let account_id = xdr::AccountId::from_str(account)
            .map_err(|_| operation::Error::InvalidField("account".into()))?;
        let key = xdr::LedgerKey::Trustline(xdr::LedgerKeyTrustLine {
            account_id,
            asset: trustline.into(),
        });
        self.revoke_ledger_key_sponsorship(key)
    }

    /// Revoke sponsorship for the offer respresented by `seller` and `offer_id`
    ///
    /// Threshold: Medium
    pub fn revoke_offer_sponsorship(
        &self,
        seller: &str,
        offer_id: i64,
    ) -> Result<xdr::Operation, operation::Error> {
        let seller_id = xdr::AccountId::from_str(seller)
            .map_err(|_| operation::Error::InvalidField("seller".into()))?;
        let key = xdr::LedgerKey::Offer(xdr::LedgerKeyOffer {
            seller_id,
            offer_id,
        });
        self.revoke_ledger_key_sponsorship(key)
    }

    /// Revoke sponsorship for the data entry `name` on the `account`
    ///
    /// Threshold: Medium
    pub fn revoke_data_sponsorship(
        &self,
        account: &str,
        name: &str,
    ) -> Result<xdr::Operation, operation::Error> {
        let account_id = xdr::AccountId::from_str(account)
            .map_err(|_| operation::Error::InvalidField("account".into()))?;
        let data_name = xdr::String64(
            name.try_into()
                .map_err(|_| operation::Error::InvalidField("name".into()))?,
        );
        let key = xdr::LedgerKey::Data(xdr::LedgerKeyData {
            account_id,
            data_name,
        });
        self.revoke_ledger_key_sponsorship(key)
    }

    /// Revoke sponsorship for the claimbable balance `balance_id`
    ///
    /// Threshold: Medium
    pub fn revoke_claimable_balance_sponsorship(
        &self,
        balance_id: &str,
    ) -> Result<xdr::Operation, operation::Error> {
        let xdr_balance_id = xdr::ClaimableBalanceId::from_str(balance_id)
            .map_err(|_| operation::Error::InvalidField("balance_id".into()))?;
        let key = xdr::LedgerKey::ClaimableBalance(xdr::LedgerKeyClaimableBalance {
            balance_id: xdr_balance_id,
        });
        self.revoke_ledger_key_sponsorship(key)
    }

    /// Revoke sponsorship for the [key](xdr::LedgerKey)
    ///
    /// Threshold: Medium
    fn revoke_ledger_key_sponsorship(
        &self,
        key: xdr::LedgerKey,
    ) -> Result<xdr::Operation, operation::Error> {
        let body =
            xdr::OperationBody::RevokeSponsorship(xdr::RevokeSponsorshipOp::LedgerEntry(key));

        Ok(xdr::Operation {
            source_account: self.source.clone(),
            body,
        })
    }
}

#[cfg(test)]
mod tests {

    use stellar_strkey::{ed25519::SignedPayload, HashX, PreAuthTx, Strkey};

    use crate::{
        asset::{Asset, AssetBehavior},
        hashing::{self, HashingBehavior},
        keypair::{Keypair, KeypairBehavior},
        liquidity_pool_asset::{LiquidityPoolAsset, LiquidityPoolAssetBehavior},
        operation::Operation,
        xdr,
    };

    #[test]
    fn test_revoke_signer_public_key() {
        let a1 = Keypair::random().unwrap().public_key();
        let a2 = Keypair::random().unwrap();
        let signer = Keypair::random().unwrap();

        let op = Operation::with_source(&a1)
            .unwrap()
            .revoke_signer_sponsorship(&a2.public_key(), &signer.public_key())
            .unwrap();

        if let xdr::OperationBody::RevokeSponsorship(xdr::RevokeSponsorshipOp::Signer(
            xdr::RevokeSponsorshipOpSigner {
                account_id: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(pk))),
                signer_key: xdr::SignerKey::Ed25519(xdr::Uint256(sk)),
            },
        )) = op.body
        {
            assert_eq!(a2.raw_public_key(), &pk.to_vec());
            assert_eq!(signer.raw_public_key(), &sk.to_vec());
            //
        } else {
            panic!("Fail")
        }
    }
    #[test]
    fn test_revoke_signer_payload() {
        let a1 = Keypair::random().unwrap().public_key();
        let a2 = Keypair::random().unwrap();
        let data = "PAY LOAD".as_bytes();
        let signer = Keypair::random().unwrap();
        let signed_payload = signer.sign_payload_decorated(data);

        let payload = Strkey::SignedPayloadEd25519(SignedPayload {
            ed25519: *signer.raw_public_key().last_chunk::<32>().unwrap(),
            payload: signed_payload.signature.to_vec(),
        })
        .to_string();

        let op = Operation::with_source(&a1)
            .unwrap()
            .revoke_signer_sponsorship(&a2.public_key(), &payload)
            .unwrap();

        if let xdr::OperationBody::RevokeSponsorship(xdr::RevokeSponsorshipOp::Signer(
            xdr::RevokeSponsorshipOpSigner {
                account_id: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(pk))),
                signer_key:
                    xdr::SignerKey::Ed25519SignedPayload(xdr::SignerKeyEd25519SignedPayload {
                        ed25519,
                        payload,
                    }),
            },
        )) = op.body
        {
            assert_eq!(a2.raw_public_key(), &pk.to_vec());
            assert_eq!(&signed_payload.signature.to_vec(), &payload.to_vec());
            //
        } else {
            panic!("Fail")
        }
    }
    #[test]
    fn test_revoke_signer_preauth() {
        let a1 = Keypair::random().unwrap().public_key();
        let a2 = Keypair::random().unwrap();
        let signer = Strkey::PreAuthTx(PreAuthTx([0; 32])).to_string();

        let op = Operation::with_source(&a1)
            .unwrap()
            .revoke_signer_sponsorship(&a2.public_key(), &signer)
            .unwrap();

        if let xdr::OperationBody::RevokeSponsorship(xdr::RevokeSponsorshipOp::Signer(
            xdr::RevokeSponsorshipOpSigner {
                account_id: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(pk))),
                signer_key: xdr::SignerKey::PreAuthTx(xdr::Uint256(txhash)),
            },
        )) = op.body
        {
            assert_eq!([0; 32], txhash);
            //
        } else {
            panic!("Fail")
        }
    }
    #[test]
    fn test_revoke_signer_hash() {
        let a1 = Keypair::random().unwrap().public_key();
        let a2 = Keypair::random().unwrap();
        let hash = hashing::Sha256Hasher::hash("DATA");
        let signer = Strkey::HashX(HashX(hash)).to_string();

        let op = Operation::with_source(&a1)
            .unwrap()
            .revoke_signer_sponsorship(&a2.public_key(), &signer)
            .unwrap();

        if let xdr::OperationBody::RevokeSponsorship(xdr::RevokeSponsorshipOp::Signer(
            xdr::RevokeSponsorshipOpSigner {
                account_id: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(pk))),
                signer_key: xdr::SignerKey::HashX(xdr::Uint256(h)),
            },
        )) = op.body
        {
            assert_eq!(hash, h);
            //
        } else {
            panic!("Fail")
        }
    }

    #[test]
    fn test_revoke_account() {
        let a1 = Keypair::random().unwrap().public_key();
        let a2 = Keypair::random().unwrap();

        let op = Operation::with_source(&a1)
            .unwrap()
            .revoke_account_sponsorship(&a2.public_key())
            .unwrap();

        if let xdr::OperationBody::RevokeSponsorship(xdr::RevokeSponsorshipOp::LedgerEntry(
            xdr::LedgerKey::Account(xdr::LedgerKeyAccount {
                account_id: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(pk))),
            }),
        )) = op.body
        {
            assert_eq!(a2.raw_public_key(), &pk.to_vec());
            //
        } else {
            panic!("Fail")
        }
    }

    #[test]
    fn test_revoke_asset_trustline() {
        let a1 = Keypair::random().unwrap().public_key();
        let a2 = Keypair::random().unwrap();
        let a_asset = Asset::new("TEST", Some(&a1)).unwrap();

        let op = Operation::with_source(&a1)
            .unwrap()
            .revoke_trustline_sponsorship(&a2.public_key(), &a_asset)
            .unwrap();

        if let xdr::OperationBody::RevokeSponsorship(xdr::RevokeSponsorshipOp::LedgerEntry(
            xdr::LedgerKey::Trustline(xdr::LedgerKeyTrustLine {
                account_id: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(pk))),
                asset,
            }),
        )) = op.body
        {
            assert_eq!(a2.raw_public_key(), &pk.to_vec());
            assert_eq!(asset, a_asset.into());

            //
        } else {
            panic!("Fail")
        }
    }
    #[test]
    fn test_revoke_liquidity_trustline() {
        let a1 = Keypair::random().unwrap().public_key();
        let a2 = Keypair::random().unwrap();
        let asset_a = Asset::new("TEST", Some(&a1)).unwrap();
        let asset_b = Asset::new("ANOTHER", Some(&a1)).unwrap();
        let liq_asset = LiquidityPoolAsset::new(asset_a, asset_b, 30).unwrap();

        let op = Operation::with_source(&a1)
            .unwrap()
            .revoke_trustline_sponsorship(&a2.public_key(), &liq_asset)
            .unwrap();

        if let xdr::OperationBody::RevokeSponsorship(xdr::RevokeSponsorshipOp::LedgerEntry(
            xdr::LedgerKey::Trustline(xdr::LedgerKeyTrustLine {
                account_id: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(pk))),
                asset,
            }),
        )) = op.body
        {
            assert_eq!(a2.raw_public_key(), &pk.to_vec());
            assert_eq!(asset, liq_asset.into());

            //
        } else {
            panic!("Fail")
        }
    }

    #[test]
    fn test_revoke_offer() {
        let a1 = Keypair::random().unwrap().public_key();
        let a2 = Keypair::random().unwrap();
        let id = 54;

        let op = Operation::with_source(&a1)
            .unwrap()
            .revoke_offer_sponsorship(&a2.public_key(), id)
            .unwrap();

        if let xdr::OperationBody::RevokeSponsorship(xdr::RevokeSponsorshipOp::LedgerEntry(
            xdr::LedgerKey::Offer(xdr::LedgerKeyOffer {
                seller_id: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(pk))),
                offer_id,
            }),
        )) = op.body
        {
            assert_eq!(a2.raw_public_key(), &pk.to_vec());
            assert_eq!(offer_id, id);

            //
        } else {
            panic!("Fail")
        }
    }

    #[test]
    fn test_revoke_data() {
        let a1 = Keypair::random().unwrap().public_key();
        let a2 = Keypair::random().unwrap();
        let name = "My entry";

        let op = Operation::with_source(&a1)
            .unwrap()
            .revoke_data_sponsorship(&a2.public_key(), name)
            .unwrap();

        if let xdr::OperationBody::RevokeSponsorship(xdr::RevokeSponsorshipOp::LedgerEntry(
            xdr::LedgerKey::Data(xdr::LedgerKeyData {
                account_id: xdr::AccountId(xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(pk))),
                data_name,
            }),
        )) = op.body
        {
            assert_eq!(a2.raw_public_key(), &pk.to_vec());
            assert_eq!(data_name.to_string(), name);

            //
        } else {
            panic!("Fail")
        }
    }

    #[test]
    fn test_revoke_claimable_balance() {
        let a1 = Keypair::random().unwrap().public_key();
        let a2 = Keypair::random().unwrap();
        let balance_id = "0000000045e0365c3c292b267a0fdfc863f5bf63b2283a19be86f72ec1256b6bc68f678e";

        let op = Operation::with_source(&a1)
            .unwrap()
            .revoke_claimable_balance_sponsorship(balance_id)
            .unwrap();

        if let xdr::OperationBody::RevokeSponsorship(xdr::RevokeSponsorshipOp::LedgerEntry(
            xdr::LedgerKey::ClaimableBalance(xdr::LedgerKeyClaimableBalance {
                balance_id: xdr::ClaimableBalanceId::ClaimableBalanceIdTypeV0(xdr::Hash(h)),
            }),
        )) = op.body
        {
            assert_eq!(h, hex::decode(balance_id).unwrap().as_slice()[4..]);

            //
        } else {
            panic!("Fail")
        }
    }
}
