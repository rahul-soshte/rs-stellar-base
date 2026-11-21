//! Construct, hash and sign fee-bump transactions without changing the inner envelope.

use std::{error::Error, fmt, str::FromStr};

use crate::{
    hashing::{HashingBehavior, Sha256Hasher},
    keypair::{Keypair, KeypairBehavior},
    transaction::Transaction,
    xdr::{self, WriteXdr},
};

/// A failure constructing, encoding or signing a fee bump.
#[derive(Debug)]
pub enum FeeBumpError {
    /// The fee source is not a G-address or M-address.
    InvalidFeeSource,
    /// Fee bumps cannot wrap other fee bumps.
    NestedFeeBump,
    /// The supplied network base fee must be positive.
    InvalidBaseFee,
    /// The inner envelope is structurally unsuitable for a fee bump.
    InvalidInnerTransaction(&'static str),
    /// The declared Soroban resource fee is outside the protocol range.
    InvalidResourceFee(i64),
    /// The required total fee cannot be represented as an i64.
    FeeOverflow,
    /// The offered total fee is below the protocol minimum.
    InsufficientFee {
        /// Offered total fee in stroops.
        fee: i64,
        /// Required total fee in stroops.
        minimum: i64,
    },
    /// An outer envelope may contain at most twenty signatures.
    TooManySignatures,
    /// XDR encoding failed.
    Xdr(xdr::Error),
    /// A keypair could not sign, for example because it has no secret key.
    Signing(Box<dyn Error>),
}

impl fmt::Display for FeeBumpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFeeSource => {
                write!(f, "invalid fee source: expected a G-address or M-address")
            }
            Self::NestedFeeBump => write!(f, "a fee bump cannot wrap another fee bump"),
            Self::InvalidBaseFee => write!(f, "network base fee must be positive"),
            Self::InvalidInnerTransaction(reason) => {
                write!(f, "invalid inner transaction: {reason}")
            }
            Self::InvalidResourceFee(fee) => write!(f, "invalid Soroban resource fee: {fee}"),
            Self::FeeOverflow => write!(f, "required fee exceeds i64::MAX"),
            Self::InsufficientFee { fee, minimum } => {
                write!(f, "fee {fee} is below the minimum {minimum} stroops")
            }
            Self::TooManySignatures => {
                write!(f, "fee bump cannot contain more than twenty signatures")
            }
            Self::Xdr(error) => write!(f, "fee-bump XDR error: {error}"),
            Self::Signing(error) => write!(f, "fee-bump signing error: {error}"),
        }
    }
}

impl Error for FeeBumpError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Xdr(error) => Some(error),
            Self::Signing(error) => Some(error.as_ref()),
            _ => None,
        }
    }
}

/// A fee-bump transaction, preserving its signed inner and outer envelopes.
#[derive(Debug, Clone)]
pub struct FeeBumpTransaction {
    pub(crate) envelope: xdr::FeeBumpTransactionEnvelope,
    pub(crate) network_passphrase: String,
}

impl FeeBumpTransaction {
    /// Wrap an existing signed V0 or V1 transaction with an explicit fee payer.
    ///
    /// `fee` is the **total outer fee in stroops**, not a per-operation fee.
    /// `network_base_fee` is the current ledger base fee in stroops per operation;
    /// the caller supplies it because this crate does not perform network I/O.
    /// V0 envelopes are normalized to V1 without changing their signing payload.
    /// Inner signatures and transaction contents are otherwise preserved verbatim.
    ///
    /// Checks the minimum inclusion fee and the outer/inner inclusion-fee rate,
    /// adding Soroban resource fees once. Uses the current (Protocol 23+) rule
    /// allowing the outer transaction to fund a negative inner inclusion fee.
    /// This does not check account state, signatures, resource estimates, surge
    /// pricing, or the separate 10x rate needed to replace a queued transaction.
    /// The inner signatures must be for `network_passphrase`.
    ///
    /// ```
    /// use stellar_baselib::{
    ///     fee_bump_transaction::{FeeBumpError, FeeBumpTransaction},
    ///     keypair::{Keypair, KeypairBehavior},
    ///     network::{NetworkPassphrase, Networks},
    ///     xdr::TransactionEnvelope,
    /// };
    ///
    /// // Example: a one-operation inner transaction bidding 100 stroops.
    /// # fn wrap(inner: TransactionEnvelope, payer: &Keypair) -> Result<(), FeeBumpError> {
    /// let mut bump = FeeBumpTransaction::new(
    ///     &payer.public_key(), 200, inner, Networks::testnet(), 100,
    /// )?;
    /// bump.sign(std::slice::from_ref(payer))?;
    /// let signed_envelope = bump.to_envelope();
    /// let inner_hash = bump.inner_hash()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(
        fee_source: &str,
        fee: i64,
        inner: xdr::TransactionEnvelope,
        network_passphrase: &str,
        network_base_fee: i64,
    ) -> Result<Self, FeeBumpError> {
        let fee_source =
            xdr::MuxedAccount::from_str(fee_source).map_err(|_| FeeBumpError::InvalidFeeSource)?;
        let inner = match inner {
            xdr::TransactionEnvelope::Tx(inner) => inner,
            xdr::TransactionEnvelope::TxV0(inner) => xdr::TransactionV1Envelope {
                tx: xdr::Transaction {
                    source_account: xdr::MuxedAccount::Ed25519(inner.tx.source_account_ed25519),
                    fee: inner.tx.fee,
                    seq_num: inner.tx.seq_num,
                    cond: inner
                        .tx
                        .time_bounds
                        .map_or(xdr::Preconditions::None, xdr::Preconditions::Time),
                    memo: inner.tx.memo,
                    operations: inner.tx.operations,
                    ext: xdr::TransactionExt::V0,
                },
                signatures: inner.signatures,
            },
            xdr::TransactionEnvelope::TxFeeBump(_) => return Err(FeeBumpError::NestedFeeBump),
        };
        let minimum = minimum_fee(&inner.tx, network_base_fee)?;
        if fee < minimum {
            return Err(FeeBumpError::InsufficientFee { fee, minimum });
        }
        Ok(Self {
            envelope: xdr::FeeBumpTransactionEnvelope {
                tx: xdr::FeeBumpTransaction {
                    fee_source,
                    fee,
                    inner_tx: xdr::FeeBumpTransactionInnerTx::Tx(inner),
                    ext: xdr::FeeBumpTransactionExt::V0,
                },
                signatures: xdr::VecM::default(),
            },
            network_passphrase: network_passphrase.to_owned(),
        })
    }

    /// The complete envelope, including inner and outer signatures.
    pub fn envelope(&self) -> &xdr::FeeBumpTransactionEnvelope {
        &self.envelope
    }

    /// The network used to interpret this transaction.
    pub fn network_passphrase(&self) -> &str {
        &self.network_passphrase
    }

    /// The signed inner V1 envelope, without any reconstruction or mutation.
    pub fn inner_envelope(&self) -> &xdr::TransactionV1Envelope {
        match &self.envelope.tx.inner_tx {
            xdr::FeeBumpTransactionInnerTx::Tx(inner) => inner,
        }
    }

    /// Return the complete transaction envelope, including both sets of signatures.
    pub fn to_envelope(&self) -> xdr::TransactionEnvelope {
        xdr::TransactionEnvelope::TxFeeBump(self.envelope.clone())
    }

    /// The network-specific signature payload tagged `TxFeeBump`.
    pub fn signature_base(&self) -> Result<Vec<u8>, FeeBumpError> {
        self.payload(
            xdr::TransactionSignaturePayloadTaggedTransaction::TxFeeBump(self.envelope.tx.clone()),
        )
    }

    /// The outer transaction signing hash (not the hash of the signed envelope).
    pub fn hash(&self) -> Result<[u8; 32], FeeBumpError> {
        Ok(Sha256Hasher::hash(self.signature_base()?))
    }

    /// The inner transaction signing hash, independent of the outer fee and payer.
    pub fn inner_hash(&self) -> Result<[u8; 32], FeeBumpError> {
        Ok(Sha256Hasher::hash(self.payload(
            xdr::TransactionSignaturePayloadTaggedTransaction::Tx(self.inner_envelope().tx.clone()),
        )?))
    }

    fn payload(
        &self,
        tagged_transaction: xdr::TransactionSignaturePayloadTaggedTransaction,
    ) -> Result<Vec<u8>, FeeBumpError> {
        xdr::TransactionSignaturePayload {
            network_id: xdr::Hash(Sha256Hasher::hash(self.network_passphrase.as_bytes())),
            tagged_transaction,
        }
        .to_xdr(xdr::Limits::none())
        .map_err(FeeBumpError::Xdr)
    }

    /// Add outer signatures without changing the inner envelope.
    ///
    /// Signing is atomic: a missing secret key or too many signatures leaves
    /// the envelope unchanged. Signers need not be the fee-source master key
    /// (the fee source may use multisig); account thresholds are checked on-chain.
    pub fn sign(&mut self, keypairs: &[Keypair]) -> Result<(), FeeBumpError> {
        if keypairs.len() > 20 - self.envelope.signatures.len() {
            return Err(FeeBumpError::TooManySignatures);
        }
        let hash = self.hash()?;
        let mut signatures = self.envelope.signatures.to_vec();
        for keypair in keypairs {
            let signature = keypair.sign(&hash).map_err(FeeBumpError::Signing)?;
            let key = keypair.raw_pubkey();
            signatures.push(xdr::DecoratedSignature {
                hint: xdr::SignatureHint([key[28], key[29], key[30], key[31]]),
                signature: xdr::Signature::try_from(signature).map_err(FeeBumpError::Xdr)?,
            });
        }
        self.envelope.signatures = signatures.try_into().map_err(FeeBumpError::Xdr)?;
        Ok(())
    }

    /// Recover the inner transaction without discarding its signatures.
    pub fn inner_transaction(&self) -> Transaction {
        Transaction::from_v1_envelope(self.inner_envelope().clone(), &self.network_passphrase)
    }
}

fn minimum_fee(inner: &xdr::Transaction, base_fee: i64) -> Result<i64, FeeBumpError> {
    if base_fee <= 0 {
        return Err(FeeBumpError::InvalidBaseFee);
    }
    if inner.operations.is_empty() {
        return Err(FeeBumpError::InvalidInnerTransaction("no operations"));
    }
    let has_soroban = inner.operations.iter().any(|op| {
        matches!(
            op.body,
            xdr::OperationBody::InvokeHostFunction(_)
                | xdr::OperationBody::ExtendFootprintTtl(_)
                | xdr::OperationBody::RestoreFootprint(_)
        )
    });
    let resource_fee = match (&inner.ext, has_soroban, inner.operations.len()) {
        (xdr::TransactionExt::V0, false, _) => 0,
        (xdr::TransactionExt::V1(data), true, 1) => {
            // Stellar Core's XDRProvidesValidFee caps the declared resource fee.
            if !(0..=(1_i64 << 50)).contains(&data.resource_fee) {
                return Err(FeeBumpError::InvalidResourceFee(data.resource_fee));
            }
            data.resource_fee
        }
        _ => {
            return Err(FeeBumpError::InvalidInnerTransaction(
                "Soroban transactions require exactly one Soroban operation and Soroban data",
            ))
        }
    };

    // Core compares inclusion-fee rates, excluding resource fees from BOTH
    // envelopes. Protocol 23+ permits negative inner inclusion fees.
    // required = resources + max(base * (n + 1), ceil(max(innerFee-resources, 0) * (n+1) / n))
    let operations = inner.operations.len() as i64;
    let outer_operations = operations + 1;
    let network_minimum = base_fee
        .checked_mul(outer_operations)
        .ok_or(FeeBumpError::FeeOverflow)?;
    let inner_inclusion = (i64::from(inner.fee) - resource_fee).max(0);
    let rate_minimum = inner_inclusion
        .checked_mul(outer_operations)
        .and_then(|fee| fee.checked_add(operations - 1))
        .ok_or(FeeBumpError::FeeOverflow)?
        / operations;
    resource_fee
        .checked_add(network_minimum.max(rate_minimum))
        .ok_or(FeeBumpError::FeeOverflow)
}

#[cfg(test)]
mod tests;
