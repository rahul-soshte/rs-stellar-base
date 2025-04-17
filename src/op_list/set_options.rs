use std::{ops::BitOr, str::FromStr};

use crate::{
    operation::{self, Operation},
    xdr,
};

#[derive(Debug, Clone, Copy)]
pub enum AccountFlags {
    AuthRequired = 1,
    AuthRevocable = 2,
    AuthImmutable = 4,
    ClawbackEnabled = 8,
}

impl BitOr for AccountFlags {
    type Output = u32;

    fn bitor(self, rhs: Self) -> Self::Output {
        self as u32 | rhs as u32
    }
}

impl From<AccountFlags> for u32 {
    fn from(flag: AccountFlags) -> Self {
        flag as u32
    }
}

impl Operation {
    /// Set options for an account such as flags, inflation destination, signers, home domain,
    /// and master key weight
    #[allow(clippy::too_many_arguments)]
    pub fn set_options(
        &self,
        inflation_dest: Option<&str>,
        clear_flags: impl Into<Option<u32>>,
        set_flags: impl Into<Option<u32>>,
        master_weight: impl Into<Option<u8>>,
        low_threshold: impl Into<Option<u8>>,
        med_threshold: impl Into<Option<u8>>,
        high_threshold: impl Into<Option<u8>>,
        home_domain: Option<&str>,
        signer: Option<(&str, u8)>,
    ) -> Result<xdr::Operation, operation::Error> {
        //
        let inflation_dest = match inflation_dest {
            Some(dest) => {
                let account_id = xdr::AccountId::from_str(dest)
                    .map_err(|_| operation::Error::InvalidField("inflation_dest".into()))?;
                Some(account_id)
            }
            _ => None,
        };
        let home_domain = match home_domain {
            Some(domain) => {
                let hd = xdr::String32(
                    domain
                        .try_into()
                        .map_err(|_| operation::Error::InvalidField("home_domain".into()))?,
                );
                Some(hd)
            }
            _ => None,
        };
        let signer = match signer {
            Some((account, weight)) => {
                let s = xdr::Signer {
                    key: xdr::SignerKey::from_str(account)
                        .map_err(|_| operation::Error::InvalidField("signer".into()))?,
                    weight: weight as u32,
                };
                Some(s)
            }
            _ => None,
        };
        let body = xdr::OperationBody::SetOptions(xdr::SetOptionsOp {
            inflation_dest,
            clear_flags: clear_flags.into(),
            set_flags: set_flags.into(),
            master_weight: master_weight.into().map(|w| w as u32),
            low_threshold: low_threshold.into().map(|w| w as u32),
            med_threshold: med_threshold.into().map(|w| w as u32),
            high_threshold: high_threshold.into().map(|w| w as u32),
            home_domain,
            signer,
        });
        Ok(xdr::Operation {
            source_account: self.source.clone(),
            body,
        })
    }

    /// Set the [AccountFlags] of the source account
    ///
    /// Multiple flags can be combined using logical or.
    pub fn set_account_flags(
        &self,
        flags: impl Into<u32>,
    ) -> Result<xdr::Operation, operation::Error> {
        self.set_options(None, None, flags.into(), None, None, None, None, None, None)
    }

    /// Clear the [AccountFlags] of the source account
    ///
    /// Multiple flags can be combined using logical or.
    pub fn clear_account_flags(&self, flags: u32) -> Result<xdr::Operation, operation::Error> {
        self.set_options(None, flags, None, None, None, None, None, None, None)
    }

    /// Set the weight of the master key of the source account
    ///
    /// The `weight` is a number from 0-255 (inclusive) representing the weight of the master key.
    /// If the weight of the master key is updated to 0, it is effectively disabled.
    ///
    /// If the master key’s weight is set at 0, it cannot be used to sign transactions, even for
    /// operations with a threshold value of 0.
    ///
    /// Be very careful setting your master key weight to 0. Doing so may permanently lock you out
    /// of your account (although if there are other signers listed on the account, they can still
    /// continue to sign transactions.)
    pub fn set_master_weight(&self, weight: u8) -> Result<xdr::Operation, operation::Error> {
        self.set_options(None, None, None, weight, None, None, None, None, None)
    }

    /// Set the `low`, `med` and `high` thresholds of the source account.
    ///
    /// The threshold is a number from 0-255 (inclusive) representing the signature weight required
    /// to authorize operations that have the said threshold level (Low, Medium or High).
    pub fn set_account_thresholds(
        &self,
        low: u8,
        med: u8,
        high: u8,
    ) -> Result<xdr::Operation, operation::Error> {
        self.set_options(None, None, None, None, low, med, high, None, None)
    }

    /// Add, update, or remove a signer from the source account.
    ///
    /// Signer weight is a number from 0-255 (inclusive). The signer is deleted if the weight is 0.
    ///
    /// The `signer` can be:
    /// - [PublicKeyEd25519](stellar_strkey::Strkey::PublicKeyEd25519)
    /// - [PreAuthTx](stellar_strkey::Strkey::PreAuthTx)
    /// - [HashX](stellar_strkey::Strkey::HashX)
    /// - [SignedPayloadEd25519](stellar_strkey::Strkey::SignedPayloadEd25519)
    pub fn set_signer(&self, signer: &str, weight: u8) -> Result<xdr::Operation, operation::Error> {
        self.set_options(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some((signer, weight)),
        )
    }

    /// Sets the home domain of the source account.
    pub fn set_home_domain(&self, home_domain: &str) -> Result<xdr::Operation, operation::Error> {
        self.set_options(
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            Some(home_domain),
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::operation::Operation;

    use super::AccountFlags;

    #[test]
    fn test_set_account_flags() {
        let op = Operation::new()
            .set_account_flags(AccountFlags::AuthImmutable)
            .unwrap();
    }
}
