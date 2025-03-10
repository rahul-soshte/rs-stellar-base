use std::{cell::RefCell, rc::Rc};

use stellar_baselib::{
    account::{Account, AccountBehavior},
    keypair::{Keypair, KeypairBehavior},
    network::{NetworkPassphrase, Networks},
    operation::{Operation, OperationBehavior},
    transaction::TransactionBehavior,
    transaction_builder::{TransactionBuilder, TransactionBuilderBehavior},
    xdr::{Limits, WriteXdr},
};

pub fn main() {
    let kp = Keypair::random().unwrap();
    println!("Secret key: {}", kp.secret_key().unwrap());
    println!("Public key: {}", kp.public_key());
    let sequence = "0";
    let source_account = Rc::new(RefCell::new(
        Account::new(&kp.public_key(), sequence).unwrap(),
    ));
    let network = Networks::testnet();
    let mut builder = TransactionBuilder::new(source_account, network, None);

    let destination = Keypair::random().unwrap().public_key();
    builder
        .fee(100u32)
        .add_operation(Operation::new(None).account_merge(destination).unwrap());

    let mut tx = builder.build();
    tx.sign(&[kp]);

    let xdr = tx
        .to_envelope()
        .unwrap()
        .to_xdr_base64(Limits::none())
        .unwrap();
    println!("Account Merge XDR: {xdr}");
}
