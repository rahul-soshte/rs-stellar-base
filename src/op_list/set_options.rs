use std::{ops::BitOr, str::FromStr};

use crate::{
    operation::{self, Operation},
    xdr,
};

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
}
