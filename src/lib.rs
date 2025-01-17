#![allow(unused)]
//! A low-level library that offers a comprehensive set of functions
//! for reading, writing, hashing, and signing primitive XDR constructs
//! utilized in the Stellar network.
//! It provides a nice abstraction for building and signing transactions
pub mod account;
pub mod address;
pub mod asset;
pub mod claimant;
pub mod contract;
pub mod get_liquidity_pool;
pub mod hashing;
pub mod keypair;
pub mod liquidity_pool_asset;
pub mod liquidity_pool_id;
pub mod memo;
pub mod muxed_account;
pub mod network;
pub mod op_list;
pub mod operation;
pub mod signer_key;
pub mod signing;
pub mod soroban;
pub mod soroban_data_builder;
pub mod transaction;
pub mod transaction_builder;
pub mod utils;
pub mod xdr {
    /*
     * Why no consistent naming here?
     */
    #[cfg(not(feature = "next"))]
    pub use stellar_xdr::curr::ExtensionPoint as SorobanTransactionDataExt;

    #[cfg(not(feature = "next"))]
    pub use stellar_xdr::curr::*;

    #[cfg(feature = "next")]
    pub use stellar_xdr::next::SorobanTransactionDataExt;

    #[cfg(feature = "next")]
    pub use stellar_xdr::next::*;
}
