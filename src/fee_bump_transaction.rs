//! Fee-bump transactions recovered from transaction envelopes.

use crate::{transaction::Transaction, xdr};

/// A fee-bump transaction, preserving its signed inner and outer envelopes.
#[derive(Debug, Clone)]
pub struct FeeBumpTransaction {
    pub(crate) envelope: xdr::FeeBumpTransactionEnvelope,
    pub(crate) network_passphrase: String,
}

impl FeeBumpTransaction {
    /// The complete envelope, including inner and outer signatures.
    pub fn envelope(&self) -> &xdr::FeeBumpTransactionEnvelope {
        &self.envelope
    }

    /// The network used to interpret this transaction.
    pub fn network_passphrase(&self) -> &str {
        &self.network_passphrase
    }

    /// Recover the inner transaction without discarding its signatures.
    pub fn inner_transaction(&self) -> Transaction {
        match &self.envelope.tx.inner_tx {
            xdr::FeeBumpTransactionInnerTx::Tx(inner) => {
                Transaction::from_v1_envelope(inner.clone(), &self.network_passphrase)
            }
        }
    }
}
