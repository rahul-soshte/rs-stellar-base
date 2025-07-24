#![allow(unused)]
//! A low-level library that offers a comprehensive set of functions
//! for reading, writing, hashing, and signing primitive XDR constructs
//! utilized in the Stellar network.
//! It provides a nice abstraction for building and signing transactions
/// `Account` represents a single account in the Stellar network and its sequence number.
pub mod account;
/// `Address` represents a single address in the Stellar network.
pub mod address;
/// Asset class represents an asset, either the native asset (`XLM`)
/// or an asset code / issuer account ID pair
pub mod asset;
pub mod claimant;
/// `Contract` represents a single contract in the Stellar network
pub mod contract;
pub mod get_liquidity_pool;
pub mod hashing;
pub mod keypair;
pub mod liquidity_pool_asset;
pub mod liquidity_pool_id;
pub mod memo;
pub mod muxed_account;
pub mod network;
pub mod operation;
pub mod signer_key;
pub mod signing;
pub mod soroban;
pub mod soroban_data_builder;
pub mod transaction;
/// Builder pattern to construct new transactions
/// that interact with Stellar environment
pub mod transaction_builder;
pub mod utils;

/// Re-exporting XDR from stellar-xdr
pub mod xdr {
    /*
     * Why no consistent naming here?
     */
    // #[cfg(not(feature = "next"))]
    // pub use stellar_xdr::curr::ExtensionPoint as SorobanTransactionDataExt;

    #[cfg(not(feature = "next"))]
    pub use stellar_xdr::curr::*;

    // #[cfg(feature = "next")]
    // pub use stellar_xdr::next::SorobanTransactionDataExt;

    #[cfg(feature = "next")]
    pub use stellar_xdr::next::*;
}

mod op_list;
