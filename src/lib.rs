#![allow(unused)]
//! A low-level library that offers a comprehensive set of functions 
//! for reading, writing, hashing, and signing primitive XDR constructs 
//! utilized in the Stellar network.
//! It provides a nice abstraction for building and signing transactions
pub mod account;
pub mod hashing;
pub mod keypair;
pub mod network;
pub mod signing;
pub mod xdr;
pub mod memo;
pub mod utils;
pub mod operations;
pub mod operation;
