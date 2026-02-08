# Stellar Base Library

![Crates.io](https://img.shields.io/crates/v/stellar-baselib)
![Crates.io](https://img.shields.io/crates/l/stellar-baselib)
![Crates.io](https://img.shields.io/crates/d/stellar-baselib)

A library that offers a comprehensive set of functions for reading, writing, hashing, and signing primitive XDR constructs utilized in the Stellar network. it provides a nice abstraction for building and signing transactions

**This project is currently production and is compatible with Protocol 23 and you can use it for buidling and signing transactions that involve interacting with Soroban and also supports all stellar classic operations.**

## Quickstart

Add this to your Cargo.toml:

```toml
[dependencies]
stellar-baselib = "0.5.6"
```

And this to your code:

```rust
use stellar_baselib::*;
```

## How to run tests

```bash
cargo test
```

## Coding Best Practices Used

1. All Rust code is linted with Clippy with the command `cargo clippy`. If preferred to ignore its advice, do so explicitly:
   `#[allow(clippy::too_many_arguments)]`

2. All rust code is formatted with `cargo fmt`. rustfmt.toml defines the expected format.

3. Function and local variable names follow snake_case. Structs or Enums follow CamelCase and Constants have all capital letters.
