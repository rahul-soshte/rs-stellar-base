use super::*;
use crate::network::{NetworkPassphrase, Networks};

fn key() -> Keypair {
    Keypair::from_raw_ed25519_seed(&[9; 32]).unwrap()
}

fn fixture() -> xdr::TransactionV1Envelope {
    let source = xdr::MuxedAccount::Ed25519(xdr::Uint256(key().raw_pubkey()));
    xdr::TransactionV1Envelope {
        tx: xdr::Transaction {
            source_account: source.clone(),
            fee: 100,
            seq_num: xdr::SequenceNumber(i64::MAX),
            cond: xdr::Preconditions::None,
            memo: xdr::Memo::Text(vec![0, 255, 128].try_into().unwrap()),
            operations: vec![xdr::Operation {
                source_account: Some(source.clone()),
                body: xdr::OperationBody::Payment(xdr::PaymentOp {
                    destination: source,
                    asset: xdr::Asset::Native,
                    amount: 123,
                }),
            }]
            .try_into()
            .unwrap(),
            ext: xdr::TransactionExt::V0,
        },
        signatures: xdr::VecM::default(),
    }
}

fn payload(tagged_transaction: xdr::TransactionSignaturePayloadTaggedTransaction) -> Vec<u8> {
    xdr::TransactionSignaturePayload {
        network_id: xdr::Hash(Sha256Hasher::hash(Networks::testnet().as_bytes())),
        tagged_transaction,
    }
    .to_xdr(Limits::none())
    .unwrap()
}

fn signed(mut envelope: xdr::TransactionV1Envelope) -> xdr::TransactionV1Envelope {
    let hash = Sha256Hasher::hash(payload(
        xdr::TransactionSignaturePayloadTaggedTransaction::Tx(envelope.tx.clone()),
    ));
    envelope.signatures = vec![key().sign_decorated(&hash)].try_into().unwrap();
    envelope
}

fn assert_roundtrip(envelope: xdr::TransactionEnvelope) {
    let encoded = envelope.to_xdr_base64(Limits::none()).unwrap();
    let parsed = Transaction::from_xdr_envelope(&encoded, Networks::testnet()).unwrap();
    let recovered = parsed.to_envelope().unwrap();
    assert_eq!(recovered, envelope);
    assert_eq!(recovered.to_xdr_base64(Limits::none()).unwrap(), encoded);
    match (parsed, envelope) {
        (ParsedTransaction::Transaction(tx), xdr::TransactionEnvelope::Tx(original)) => {
            let expected = payload(xdr::TransactionSignaturePayloadTaggedTransaction::Tx(
                original.tx,
            ));
            assert_eq!(tx.try_signature_base().unwrap(), expected);
            assert_eq!(tx.try_hash().unwrap(), Sha256Hasher::hash(expected));
            assert_eq!(tx.hash(), tx.try_hash().unwrap());
            assert!(key().verify(&tx.hash(), original.signatures[0].signature.as_ref()));
            assert_eq!(tx.to_envelope().unwrap(), recovered);
        }
        (ParsedTransaction::Transaction(tx), xdr::TransactionEnvelope::TxV0(original)) => {
            let normalized = xdr::Transaction {
                source_account: xdr::MuxedAccount::Ed25519(original.tx.source_account_ed25519),
                fee: original.tx.fee,
                seq_num: original.tx.seq_num,
                cond: original
                    .tx
                    .time_bounds
                    .map_or(xdr::Preconditions::None, xdr::Preconditions::Time),
                memo: original.tx.memo,
                operations: original.tx.operations,
                ext: xdr::TransactionExt::V0,
            };
            let expected = payload(xdr::TransactionSignaturePayloadTaggedTransaction::Tx(
                normalized,
            ));
            assert_eq!(tx.try_signature_base().unwrap(), expected);
            assert_eq!(tx.try_hash().unwrap(), Sha256Hasher::hash(expected));
            assert!(key().verify(&tx.hash(), original.signatures[0].signature.as_ref()));
            assert_eq!(tx.to_envelope().unwrap(), recovered);
        }
        (ParsedTransaction::FeeBump(tx), xdr::TransactionEnvelope::TxFeeBump(original)) => {
            let expected =
                payload(xdr::TransactionSignaturePayloadTaggedTransaction::TxFeeBump(original.tx));
            assert_eq!(tx.signature_base().unwrap(), expected);
            assert_eq!(tx.hash().unwrap(), Sha256Hasher::hash(expected));
            assert!(key().verify(
                &tx.hash().unwrap(),
                original.signatures[0].signature.as_ref()
            ));
            let inner = tx.inner_transaction();
            assert_eq!(
                inner.to_envelope().unwrap(),
                xdr::TransactionEnvelope::Tx(tx.inner_envelope().clone())
            );
            assert_eq!(inner.try_hash().unwrap(), tx.inner_hash().unwrap());
            assert!(key().verify(&inner.hash(), inner.signatures[0].signature.as_ref()));
        }
        _ => panic!("envelope variant changed"),
    }
}

fn conditions() -> Vec<xdr::Preconditions> {
    let time = xdr::TimeBounds {
        min_time: xdr::TimePoint(10),
        max_time: xdr::TimePoint(u64::MAX),
    };
    let empty = xdr::PreconditionsV2 {
        time_bounds: None,
        ledger_bounds: None,
        min_seq_num: None,
        min_seq_age: xdr::Duration(0),
        min_seq_ledger_gap: 0,
        extra_signers: xdr::VecM::default(),
    };
    vec![
        xdr::Preconditions::None,
        xdr::Preconditions::Time(time.clone()),
        xdr::Preconditions::V2(empty.clone()),
        xdr::Preconditions::V2(xdr::PreconditionsV2 {
            time_bounds: Some(time.clone()),
            ..empty.clone()
        }),
        xdr::Preconditions::V2(xdr::PreconditionsV2 {
            ledger_bounds: Some(xdr::LedgerBounds {
                min_ledger: 1,
                max_ledger: u32::MAX,
            }),
            ..empty.clone()
        }),
        xdr::Preconditions::V2(xdr::PreconditionsV2 {
            min_seq_num: Some(xdr::SequenceNumber(42)),
            ..empty.clone()
        }),
        xdr::Preconditions::V2(xdr::PreconditionsV2 {
            time_bounds: Some(time),
            ledger_bounds: Some(xdr::LedgerBounds {
                min_ledger: 20,
                max_ledger: 100,
            }),
            min_seq_num: Some(xdr::SequenceNumber(0)),
            min_seq_age: xdr::Duration(u64::MAX),
            min_seq_ledger_gap: u32::MAX,
            extra_signers: vec![
                xdr::SignerKey::HashX(xdr::Uint256([1; 32])),
                xdr::SignerKey::Ed25519SignedPayload(xdr::SignerKeyEd25519SignedPayload {
                    ed25519: xdr::Uint256(key().raw_pubkey()),
                    payload: vec![0, 255, 1].try_into().unwrap(),
                }),
            ]
            .try_into()
            .unwrap(),
        }),
    ]
}

#[test]
fn roundtrips_signed_v0_with_all_memo_variants_and_optional_time_bounds() {
    for memo in [
        xdr::Memo::None,
        xdr::Memo::Text(vec![0, 255, 128].try_into().unwrap()),
        xdr::Memo::Id(u64::MAX),
        xdr::Memo::Hash(xdr::Hash([3; 32])),
        xdr::Memo::Return(xdr::Hash([4; 32])),
    ] {
        for time_bounds in [
            None,
            Some(xdr::TimeBounds {
                min_time: xdr::TimePoint(0),
                max_time: xdr::TimePoint(u64::MAX),
            }),
        ] {
            let mut inner = fixture();
            inner.tx.memo = memo.clone();
            inner.tx.cond = time_bounds
                .clone()
                .map_or(xdr::Preconditions::None, xdr::Preconditions::Time);
            let inner = signed(inner);
            assert_roundtrip(xdr::TransactionEnvelope::TxV0(xdr::TransactionV0Envelope {
                tx: xdr::TransactionV0 {
                    source_account_ed25519: xdr::Uint256(key().raw_pubkey()),
                    fee: inner.tx.fee,
                    seq_num: inner.tx.seq_num,
                    time_bounds,
                    memo: inner.tx.memo,
                    operations: inner.tx.operations,
                    ext: xdr::TransactionV0Ext::V0,
                },
                signatures: inner.signatures,
            }));
        }
    }
}

#[test]
fn roundtrips_signed_v1_with_every_precondition_variant_and_muxed_accounts() {
    for cond in conditions() {
        let mut inner = fixture();
        inner.tx.cond = cond;
        inner.tx.source_account = xdr::MuxedAccount::MuxedEd25519(xdr::MuxedAccountMed25519 {
            id: u64::MAX,
            ed25519: xdr::Uint256(key().raw_pubkey()),
        });
        assert_roundtrip(xdr::TransactionEnvelope::Tx(signed(inner)));
    }
}

#[test]
fn roundtrips_signed_soroban_and_fee_bump_with_exact_inner_recovery() {
    for cond in conditions() {
        let mut inner = fixture();
        inner.tx.cond = cond;
        inner.tx.operations = vec![xdr::Operation {
            source_account: None,
            body: xdr::OperationBody::RestoreFootprint(xdr::RestoreFootprintOp::default()),
        }]
        .try_into()
        .unwrap();
        inner.tx.ext = xdr::TransactionExt::V1(xdr::SorobanTransactionData {
            ext: xdr::SorobanTransactionDataExt::V1(xdr::SorobanResourcesExtV0 {
                archived_soroban_entries: vec![0].try_into().unwrap(),
            }),
            resource_fee: i64::from(u32::MAX) + 1,
            resources: xdr::SorobanResources {
                footprint: xdr::LedgerFootprint {
                    read_only: vec![xdr::LedgerKey::Account(xdr::LedgerKeyAccount {
                        account_id: key().xdr_account_id(),
                    })]
                    .try_into()
                    .unwrap(),
                    read_write: vec![xdr::LedgerKey::ContractCode(xdr::LedgerKeyContractCode {
                        hash: xdr::Hash([7; 32]),
                    })]
                    .try_into()
                    .unwrap(),
                },
                instructions: 1234,
                disk_read_bytes: 5678,
                write_bytes: 90,
                ..Default::default()
            },
            ..Default::default()
        });
        let inner = signed(inner);
        assert_roundtrip(xdr::TransactionEnvelope::Tx(inner.clone()));
        let mut bump = FeeBumpTransaction::new(
            &key().public_key(),
            i64::from(u32::MAX) + 201,
            xdr::TransactionEnvelope::Tx(inner),
            Networks::testnet(),
            100,
        )
        .unwrap();
        bump.sign(&[key()]).unwrap();
        assert_roundtrip(bump.to_envelope());
    }
}

#[test]
fn builder_keeps_ordinary_precondition_encoding_and_hashes() {
    use crate::{
        account::AccountBehavior,
        transaction_builder::{TransactionBuilder, TransactionBuilderBehavior},
    };

    for bounds in [
        None,
        Some(xdr::TimeBounds {
            min_time: xdr::TimePoint(10),
            max_time: xdr::TimePoint(100),
        }),
    ] {
        let mut source = Account::new(&key().public_key(), "41").unwrap();
        let mut builder = TransactionBuilder::new(&mut source, Networks::testnet(), None);
        builder
            .fee(100_u32)
            .add_operation(fixture().tx.operations[0].clone());
        if let Some(ref bounds) = bounds {
            builder.set_time_bounds(bounds.clone());
        }
        // Both build paths must leave V2-only fields absent, not Some(0).
        let simulation = builder.build_for_simulation();
        let built = builder.build();
        assert_eq!(
            simulation.try_to_envelope().unwrap(),
            built.try_to_envelope().unwrap()
        );
        for tx in [simulation, built] {
            let expected_cond = bounds
                .clone()
                .map_or(xdr::Preconditions::None, xdr::Preconditions::Time);
            let xdr::TransactionEnvelope::Tx(envelope) = tx.try_to_envelope().unwrap() else {
                panic!("expected V1")
            };
            assert_eq!(envelope.tx.cond, expected_cond);
            assert_eq!(
                tx.hash(),
                Sha256Hasher::hash(payload(
                    xdr::TransactionSignaturePayloadTaggedTransaction::Tx(envelope.tx)
                ))
            );
        }
    }
}

fn ordinary() -> Transaction {
    Transaction::from_v1_envelope(fixture(), Networks::testnet())
}

fn assert_invalid_field(tx: Transaction, field: &str) {
    assert!(
        matches!(tx.try_to_envelope(), Err(TransactionError::InvalidField { field: actual, .. }) if actual == field)
    );
    let boxed = tx.to_envelope().unwrap_err();
    assert!(
        matches!(boxed.downcast_ref::<TransactionError>(), Some(TransactionError::InvalidField { field: actual, .. }) if *actual == field)
    );
    assert!(tx.try_signature_base().is_err());
    assert!(tx.try_hash().is_err());
}

#[test]
fn invalid_mutable_fields_return_errors_instead_of_panicking() {
    let mut tx = ordinary();
    tx.source = None;
    assert_invalid_field(tx, "source");
    let mut tx = ordinary();
    tx.source = Some("invalid address".into());
    assert_invalid_field(tx, "source");
    let mut tx = ordinary();
    tx.sequence = None;
    assert_invalid_field(tx, "sequence");
    for sequence in ["invalid", "9223372036854775808", "-9223372036854775809"] {
        let mut tx = ordinary();
        tx.sequence = Some(sequence.into());
        assert_invalid_field(tx, "sequence");
        let mut tx = ordinary();
        tx.min_account_sequence = Some(sequence.into());
        assert_invalid_field(tx, "min_account_sequence");
    }
    let mut tx = ordinary();
    tx.envelope_type = xdr::EnvelopeType::TxFeeBump;
    assert!(matches!(
        tx.try_to_envelope(),
        Err(TransactionError::UnsupportedEnvelopeType(
            xdr::EnvelopeType::TxFeeBump
        ))
    ));
    assert!(tx.to_envelope().is_err());
    assert!(tx.try_hash().is_err());
}

#[test]
fn refuses_to_silently_drop_fields_from_v0() {
    let mut tx = ordinary();
    tx.envelope_type = xdr::EnvelopeType::TxV0;
    let mut muxed = tx.clone();
    muxed.source = Some(encode_muxed_account_to_address(
        &xdr::MuxedAccount::MuxedEd25519(xdr::MuxedAccountMed25519 {
            id: 123,
            ed25519: xdr::Uint256(key().raw_pubkey()),
        }),
    ));
    assert_invalid_field(muxed, "source");
    let mut soroban = tx.clone();
    soroban.soroban_data = Some(Default::default());
    assert_invalid_field(soroban, "soroban_data");
    tx.min_account_sequence_age = Some(0);
    assert_invalid_field(tx, "preconditions");
}

#[test]
fn oversized_collections_return_typed_encoding_errors() {
    let mut tx = ordinary();
    tx.operations = Some(vec![fixture().tx.operations[0].clone(); 101]);
    assert!(matches!(
        tx.try_to_envelope(),
        Err(TransactionError::Encoding(_))
    ));
    assert!(tx.to_envelope().is_err());
    let mut tx = ordinary();
    tx.extra_signers = Some(vec![xdr::SignerKey::HashX(xdr::Uint256([1; 32])); 3]);
    assert!(matches!(
        tx.try_to_envelope(),
        Err(TransactionError::Encoding(_))
    ));
    assert!(tx.try_hash().is_err());
    let mut tx = ordinary();
    tx.signatures = vec![key().sign_decorated(&tx.hash()); 21];
    assert!(matches!(
        tx.try_to_envelope(),
        Err(TransactionError::Encoding(_))
    ));
    assert!(tx.to_envelope().is_err());
}
