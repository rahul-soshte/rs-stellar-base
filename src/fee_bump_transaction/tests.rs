use super::*;
use crate::{
    network::{NetworkPassphrase, Networks},
    transaction::{ParsedTransaction, TransactionBehavior},
    utils::decode_encode_muxed_account::encode_muxed_account_to_address,
    xdr::{Limits, ReadXdr},
};

fn inner(operations: usize, fee: u32) -> xdr::TransactionV1Envelope {
    let payment = xdr::Operation {
        source_account: None,
        body: xdr::OperationBody::Payment(xdr::PaymentOp {
            destination: xdr::MuxedAccount::Ed25519(xdr::Uint256([2; 32])),
            asset: xdr::Asset::Native,
            amount: 7,
        }),
    };
    xdr::TransactionV1Envelope {
        tx: xdr::Transaction {
            source_account: xdr::MuxedAccount::Ed25519(xdr::Uint256([1; 32])),
            fee,
            seq_num: xdr::SequenceNumber(42),
            cond: xdr::Preconditions::None,
            memo: xdr::Memo::None,
            operations: vec![payment; operations].try_into().unwrap(),
            ext: xdr::TransactionExt::V0,
        },
        signatures: xdr::VecM::default(),
    }
}

fn payer() -> String {
    encode_muxed_account_to_address(&xdr::MuxedAccount::Ed25519(xdr::Uint256([3; 32])))
}

fn build(
    inner: xdr::TransactionV1Envelope,
    base_fee: i64,
    network_base_fee: i64,
) -> Result<FeeBumpTransaction, FeeBumpError> {
    FeeBumpTransaction::new(
        &payer(),
        base_fee,
        xdr::TransactionEnvelope::Tx(inner),
        Networks::testnet(),
        network_base_fee,
    )
}

fn soroban(resource_fee: i64, fee: u32) -> xdr::TransactionV1Envelope {
    let mut inner = inner(1, fee);
    inner.tx.operations = vec![xdr::Operation {
        source_account: None,
        body: xdr::OperationBody::RestoreFootprint(xdr::RestoreFootprintOp::default()),
    }]
    .try_into()
    .unwrap();
    inner.tx.ext = xdr::TransactionExt::V1(xdr::SorobanTransactionData {
        resource_fee,
        ..Default::default()
    });
    inner
}

#[test]
fn enforces_per_operation_fee_boundaries_and_computes_classic_totals() {
    // A 201/2 inclusion rate requires an integer bid of 101, giving a total of 303.
    for (operations, inner_fee, network_base, minimum, total) in [
        (1, 0, 100, 100, 200),
        (1, 100, 100, 100, 200),
        (1, 400, 100, 400, 800),
        (2, 200, 100, 100, 300),
        (2, 201, 100, 101, 303),
        (3, 301, 100, 101, 404),
        (100, 10_000, 100, 100, 10_100),
        (100, 10_001, 100, 101, 10_201),
        (1, 100, 250, 250, 500),
        (
            1,
            u32::MAX,
            100,
            i64::from(u32::MAX),
            2 * i64::from(u32::MAX),
        ),
    ] {
        let inner = inner(operations, inner_fee);
        let bump = build(inner.clone(), minimum, network_base).unwrap();
        assert_eq!(bump.envelope().tx.fee, total);
        assert_eq!(bump.inner_envelope(), &inner);
        assert!(matches!(build(inner, minimum - 1, network_base),
            Err(FeeBumpError::InsufficientFee { fee, minimum: required })
                if fee == minimum - 1 && required == minimum
        ));
    }
    for bid in [i64::MIN, -1, 0, 99] {
        assert!(matches!(build(inner(1, 100), bid, 100),
            Err(FeeBumpError::InsufficientFee { fee, minimum: 100 }) if fee == bid
        ));
    }
    assert_eq!(
        build(inner(1, 100), i64::MAX / 2, 100)
            .unwrap()
            .envelope()
            .tx
            .fee,
        i64::MAX - 1
    );
}

#[test]
fn accounts_for_soroban_resources_once_and_allows_negative_inner_inclusion() {
    for (resources, inner_fee, minimum, total) in [
        (0, 100, 100, 200),
        (1_000, 1_000, 100, 1_200),
        (1_000, 1_100, 100, 1_200),
        (1_000, 1_400, 400, 1_800),
        (5_000, 100, 100, 5_200),
        (
            i64::from(u32::MAX) + 1_000,
            u32::MAX,
            100,
            i64::from(u32::MAX) + 1_200,
        ),
        (1_i64 << 50, 0, 100, (1_i64 << 50) + 200),
    ] {
        let inner = soroban(resources, inner_fee);
        let bump = build(inner.clone(), minimum, 100).unwrap();
        assert_eq!(bump.envelope().tx.fee, total);
        assert_eq!(bump.inner_envelope(), &inner);
        assert!(matches!(build(inner, minimum - 1, 100),
            Err(FeeBumpError::InsufficientFee { minimum: required, .. }) if required == minimum
        ));
    }
    // A bid above the minimum still adds resources once, not once per op.
    assert_eq!(
        build(soroban(1_000, 1_400), 500, 100)
            .unwrap()
            .envelope()
            .tx
            .fee,
        2_000
    );
    for resources in [-1, (1_i64 << 50) + 1] {
        assert!(matches!(build(soroban(resources, 100), i64::MAX, 100),
            Err(FeeBumpError::InvalidResourceFee(fee)) if fee == resources
        ));
    }
}

#[test]
fn rejects_invalid_base_fees_and_overflow_without_panicking() {
    for base in [0, -1, i64::MIN] {
        assert!(matches!(
            build(inner(1, 100), 100, base),
            Err(FeeBumpError::InvalidBaseFee)
        ));
    }
    assert!(matches!(
        build(inner(1, 100), i64::MAX, i64::MAX),
        Err(FeeBumpError::FeeOverflow)
    ));
    assert!(matches!(
        build(inner(1, 100), i64::MAX / 2 + 1, 100),
        Err(FeeBumpError::FeeOverflow)
    ));
    // Inclusion multiplication fits but adding resources would overflow.
    let largest_bid = (i64::MAX - 1_000) / 2;
    assert_eq!(
        build(soroban(1_000, 100), largest_bid, 100)
            .unwrap()
            .envelope()
            .tx
            .fee,
        i64::MAX - 1
    );
    assert!(matches!(
        build(soroban(1_000, 100), largest_bid + 1, 100),
        Err(FeeBumpError::FeeOverflow)
    ));
}

#[test]
fn rejects_unsuitable_inner_transactions() {
    assert!(matches!(
        build(inner(0, 100), 100, 100),
        Err(FeeBumpError::InvalidInnerTransaction(_))
    ));
    let mut missing_data = soroban(1_000, 100);
    missing_data.tx.ext = xdr::TransactionExt::V0;
    assert!(matches!(
        build(missing_data, 100, 100),
        Err(FeeBumpError::InvalidInnerTransaction(_))
    ));
    let mut wrong_operations = inner(1, 100);
    wrong_operations.tx.ext = xdr::TransactionExt::V1(Default::default());
    assert!(matches!(
        build(wrong_operations, 100, 100),
        Err(FeeBumpError::InvalidInnerTransaction(_))
    ));
    let mut mixed = soroban(1_000, 100);
    let mut ops = mixed.tx.operations.to_vec();
    ops.extend(inner(1, 100).tx.operations.to_vec());
    mixed.tx.operations = ops.try_into().unwrap();
    assert!(matches!(
        build(mixed, 100, 100),
        Err(FeeBumpError::InvalidInnerTransaction(_))
    ));
    let bump = build(inner(1, 100), 100, 100).unwrap();
    assert!(matches!(
        FeeBumpTransaction::new(&payer(), 200, bump.to_envelope(), Networks::testnet(), 100),
        Err(FeeBumpError::NestedFeeBump)
    ));
}

#[test]
fn accepts_muxed_fee_sources_and_rejects_other_addresses() {
    let source = xdr::MuxedAccount::MuxedEd25519(xdr::MuxedAccountMed25519 {
        id: u64::MAX,
        ed25519: xdr::Uint256([3; 32]),
    });
    let address = encode_muxed_account_to_address(&source);
    let bump = FeeBumpTransaction::new(
        &address,
        100,
        xdr::TransactionEnvelope::Tx(inner(1, 100)),
        Networks::testnet(),
        100,
    )
    .unwrap();
    assert_eq!(bump.envelope().tx.fee_source, source);
    for source in [
        "",
        "not an address",
        "SAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSU2",
        "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4",
    ] {
        assert!(matches!(
            FeeBumpTransaction::new(
                source,
                100,
                xdr::TransactionEnvelope::Tx(inner(1, 100)),
                Networks::testnet(),
                100
            ),
            Err(FeeBumpError::InvalidFeeSource)
        ));
    }
}

#[test]
fn matches_independently_encoded_signature_payload_vectors() {
    let bump = build(inner(1, 100), 150, 100).unwrap();
    assert_eq!(bump.envelope().tx.fee, 300);
    assert_eq!(
        hex::encode(bump.inner_hash().unwrap()),
        "b715c9db3cbdacc3118aa9d8e13a160cdb7b3311154dd37edf17b51587682efa"
    );
    assert_eq!(
        hex::encode(bump.hash().unwrap()),
        "2779e2eb46e03ac795acb5b29f2bdfdf88cdc515a76f013b59bc9aa82da5c63c"
    );
    let payload =
        xdr::TransactionSignaturePayload::from_xdr(bump.signature_base().unwrap(), Limits::none())
            .unwrap();
    assert!(matches!(
        payload.tagged_transaction,
        xdr::TransactionSignaturePayloadTaggedTransaction::TxFeeBump(_)
    ));
}

fn sign_inner(inner: &mut xdr::TransactionV1Envelope, key: &Keypair) -> [u8; 32] {
    inner.tx.source_account = xdr::MuxedAccount::Ed25519(xdr::Uint256(key.raw_pubkey()));
    let payload = xdr::TransactionSignaturePayload {
        network_id: xdr::Hash(Sha256Hasher::hash(Networks::testnet().as_bytes())),
        tagged_transaction: xdr::TransactionSignaturePayloadTaggedTransaction::Tx(inner.tx.clone()),
    }
    .to_xdr(Limits::none())
    .unwrap();
    let hash = Sha256Hasher::hash(payload);
    inner.signatures = vec![key.sign_decorated(&hash)].try_into().unwrap();
    hash
}

#[test]
fn signs_with_a_different_payer_and_preserves_the_inner_envelope() {
    let source = Keypair::from_raw_ed25519_seed(&[1; 32]).unwrap();
    let payer = Keypair::from_raw_ed25519_seed(&[2; 32]).unwrap();
    let mut inner = inner(1, 100);
    let inner_hash = sign_inner(&mut inner, &source);
    let bytes = inner.to_xdr(Limits::none()).unwrap();
    let mut bump = FeeBumpTransaction::new(
        &payer.public_key(),
        150,
        xdr::TransactionEnvelope::Tx(inner),
        Networks::testnet(),
        100,
    )
    .unwrap();
    let hash = bump.hash().unwrap();
    bump.sign(&[payer.clone()]).unwrap();
    assert_eq!(bump.hash().unwrap(), hash);
    assert_eq!(bump.inner_hash().unwrap(), inner_hash);
    assert_eq!(bump.inner_envelope().to_xdr(Limits::none()).unwrap(), bytes);
    let outer_signature = &bump.envelope().signatures[0];
    assert!(payer.verify(&hash, outer_signature.signature.as_ref()));
    assert!(!source.verify(&hash, outer_signature.signature.as_ref()));
    assert!(!payer.verify(&inner_hash, outer_signature.signature.as_ref()));
    assert_eq!(outer_signature.hint, payer.sign_decorated(&hash).hint);
    assert!(source.verify(
        &inner_hash,
        bump.inner_envelope().signatures[0].signature.as_ref()
    ));

    let encoded = bump.to_envelope().to_xdr_base64(Limits::none()).unwrap();
    let ParsedTransaction::FeeBump(parsed) =
        Transaction::from_xdr_envelope(&encoded, Networks::testnet()).unwrap()
    else {
        panic!("expected fee bump")
    };
    assert_eq!(parsed.envelope(), bump.envelope());
    assert_eq!(parsed.hash().unwrap(), hash);
    assert_eq!(parsed.inner_hash().unwrap(), inner_hash);
}

#[test]
fn hash_commits_to_network_fee_payer_and_inner_signatures() {
    let inner = inner(1, 100);
    let bump = build(inner.clone(), 150, 100).unwrap();
    let higher = build(inner.clone(), 200, 100).unwrap();
    assert_ne!(bump.hash().unwrap(), higher.hash().unwrap());
    assert_eq!(bump.inner_hash().unwrap(), higher.inner_hash().unwrap());
    let other_payer = Keypair::from_raw_ed25519_seed(&[4; 32]).unwrap();
    let other = FeeBumpTransaction::new(
        &other_payer.public_key(),
        150,
        xdr::TransactionEnvelope::Tx(inner.clone()),
        Networks::testnet(),
        100,
    )
    .unwrap();
    assert_ne!(bump.hash().unwrap(), other.hash().unwrap());
    assert_eq!(bump.inner_hash().unwrap(), other.inner_hash().unwrap());
    let network = FeeBumpTransaction::new(
        &payer(),
        150,
        xdr::TransactionEnvelope::Tx(inner.clone()),
        Networks::public(),
        100,
    )
    .unwrap();
    assert_ne!(bump.hash().unwrap(), network.hash().unwrap());
    assert_ne!(bump.inner_hash().unwrap(), network.inner_hash().unwrap());
    let mut signed = inner;
    let key = Keypair::from_raw_ed25519_seed(&[4; 32]).unwrap();
    signed.signatures = vec![key.sign_decorated(&bump.inner_hash().unwrap())]
        .try_into()
        .unwrap();
    let signed = build(signed, 150, 100).unwrap();
    assert_ne!(bump.hash().unwrap(), signed.hash().unwrap());
    assert_eq!(bump.inner_hash().unwrap(), signed.inner_hash().unwrap());
}

#[test]
fn signing_errors_are_atomic_and_enforce_the_signature_limit() {
    let key = Keypair::from_raw_ed25519_seed(&[4; 32]).unwrap();
    let public_only = Keypair::from_public_key(&key.public_key()).unwrap();
    let mut bump = build(inner(1, 100), 150, 100).unwrap();
    let original = bump.envelope().clone();
    assert!(matches!(
        bump.sign(&[key.clone(), public_only]),
        Err(FeeBumpError::Signing(_))
    ));
    assert_eq!(bump.envelope(), &original);
    assert!(matches!(
        bump.sign(&vec![key.clone(); 21]),
        Err(FeeBumpError::TooManySignatures)
    ));
    assert_eq!(bump.envelope(), &original);
    bump.sign(&vec![key.clone(); 20]).unwrap();
    let full = bump.envelope().clone();
    assert!(matches!(
        bump.sign(&[key]),
        Err(FeeBumpError::TooManySignatures)
    ));
    assert_eq!(bump.envelope(), &full);
    bump.sign(&[]).unwrap();
    assert_eq!(bump.envelope(), &full);
}

#[test]
fn normalizes_v0_without_changing_the_inner_hash_or_signatures() {
    let key = Keypair::from_raw_ed25519_seed(&[1; 32]).unwrap();
    let mut expected = inner(1, 100);
    let bounds = xdr::TimeBounds {
        min_time: xdr::TimePoint(10),
        max_time: xdr::TimePoint(100),
    };
    expected.tx.cond = xdr::Preconditions::Time(bounds.clone());
    expected.tx.memo = xdr::Memo::Text(b"fee bump".to_vec().try_into().unwrap());
    let hash = sign_inner(&mut expected, &key);
    let legacy = xdr::TransactionV0Envelope {
        tx: xdr::TransactionV0 {
            source_account_ed25519: xdr::Uint256(key.raw_pubkey()),
            fee: expected.tx.fee,
            seq_num: expected.tx.seq_num.clone(),
            time_bounds: Some(bounds),
            memo: expected.tx.memo.clone(),
            operations: expected.tx.operations.clone(),
            ext: xdr::TransactionV0Ext::V0,
        },
        signatures: expected.signatures.clone(),
    };
    let bump = FeeBumpTransaction::new(
        &payer(),
        100,
        xdr::TransactionEnvelope::TxV0(legacy),
        Networks::testnet(),
        100,
    )
    .unwrap();
    assert_eq!(bump.inner_envelope(), &expected);
    assert_eq!(bump.inner_hash().unwrap(), hash);
    assert!(key.verify(
        &hash,
        bump.inner_envelope().signatures[0].signature.as_ref()
    ));
}

#[test]
fn preserves_signed_soroban_data_and_v2_preconditions() {
    let key = Keypair::from_raw_ed25519_seed(&[5; 32]).unwrap();
    let mut inner = soroban(1_000, 100);
    inner.tx.cond = xdr::Preconditions::V2(xdr::PreconditionsV2 {
        time_bounds: Some(xdr::TimeBounds {
            min_time: xdr::TimePoint(1),
            max_time: xdr::TimePoint(100),
        }),
        ledger_bounds: Some(xdr::LedgerBounds {
            min_ledger: 2,
            max_ledger: 100,
        }),
        min_seq_num: Some(xdr::SequenceNumber(20)),
        min_seq_age: xdr::Duration(u64::MAX),
        min_seq_ledger_gap: 3,
        extra_signers: vec![xdr::SignerKey::HashX(xdr::Uint256([7; 32]))]
            .try_into()
            .unwrap(),
    });
    let hash = sign_inner(&mut inner, &key);
    let bytes = inner.to_xdr(Limits::none()).unwrap();
    let mut bump = build(inner, 100, 100).unwrap();
    bump.sign(&[key]).unwrap();
    assert_eq!(bump.inner_hash().unwrap(), hash);
    assert_eq!(bump.inner_envelope().to_xdr(Limits::none()).unwrap(), bytes);
}
