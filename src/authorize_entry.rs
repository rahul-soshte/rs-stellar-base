use crate::hashing::{HashingBehavior, Sha256Hasher};
use crate::keypair::{Keypair, KeypairBehavior};
use crate::xdr::{
    Hash, HashIdPreimage, HashIdPreimageSorobanAuthorization,
    HashIdPreimageSorobanAuthorizationWithAddress, Limits, ScBytes, ScMap, ScMapEntry, ScSymbol,
    ScVal, SorobanAddressCredentials, SorobanAuthorizationEntry, SorobanCredentials, StringM,
    Uint256, VecM, WriteXdr,
};
use std::str::FromStr;

/// Parameters for authorizing a Soroban authorization entry.
pub struct AuthorizeEntryParams<'a> {
    pub entry: SorobanAuthorizationEntry,
    pub signer: &'a Keypair,
    pub valid_until_ledger_seq: u32,
    pub network_passphrase: &'a str,
    /// When `true`, upgrade a V1 `SOROBAN_CREDENTIALS_ADDRESS` entry to
    /// `SOROBAN_CREDENTIALS_ADDRESS_V2` (CAP-0071-02 / Protocol 27), which binds
    /// the auth to a specific address to prevent replay across accounts sharing a key.
    /// Entries that are already `AddressV2` are always signed with the V2 preimage
    /// regardless of this flag.
    pub use_address_v2: bool,
}

/// Authorize a Soroban auth entry by signing it with the given keypair.
///
/// Mirrors the behaviour of `authorizeEntry` in `js-stellar-base`:
/// - `SourceAccount` entries are returned unchanged (no signing required).
/// - `Address` (V1) entries are signed with `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION`.
///   Set `use_address_v2 = true` to upgrade the output to `AddressV2` and use
///   the address-bound preimage `ENVELOPE_TYPE_SOROBAN_AUTHORIZATION_WITH_ADDRESS`
///   (CAP-0071-02, Protocol 27+).
/// - `AddressV2` entries are always signed with the address-bound V2 preimage.
///
/// The signature is verified against the signing payload before returning,
/// matching the JS SDK behaviour.
///
/// # Errors
///
/// Returns an error string if XDR serialization, signing, or signature verification fails.
pub fn authorize_entry(
    params: AuthorizeEntryParams<'_>,
) -> Result<SorobanAuthorizationEntry, String> {
    use crate::signing::verify;

    let AuthorizeEntryParams {
        entry,
        signer,
        valid_until_ledger_seq,
        network_passphrase,
        use_address_v2,
    } = params;

    // Determine the incoming credential variant; SourceAccount needs no signing.
    let (credentials, incoming_is_v2) = match &entry.credentials {
        SorobanCredentials::SourceAccount => return Ok(entry),
        SorobanCredentials::Address(c) => (c.clone(), false),
        SorobanCredentials::AddressV2(c) => (c.clone(), true),
        SorobanCredentials::AddressWithDelegates(d) => (d.address_credentials.clone(), true),
    };

    // V2 if explicitly requested OR if the incoming entry was already V2.
    let output_v2 = use_address_v2 || incoming_is_v2;

    let network_id = Hash(Sha256Hasher::hash(network_passphrase.as_bytes()));

    let preimage = if output_v2 {
        HashIdPreimage::SorobanAuthorizationWithAddress(
            HashIdPreimageSorobanAuthorizationWithAddress {
                network_id,
                nonce: credentials.nonce,
                signature_expiration_ledger: valid_until_ledger_seq,
                address: credentials.address.clone(),
                invocation: entry.root_invocation.clone(),
            },
        )
    } else {
        HashIdPreimage::SorobanAuthorization(HashIdPreimageSorobanAuthorization {
            network_id,
            nonce: credentials.nonce,
            signature_expiration_ledger: valid_until_ledger_seq,
            invocation: entry.root_invocation.clone(),
        })
    };

    let preimage_bytes = preimage
        .to_xdr(Limits::none())
        .map_err(|e| format!("XDR serialization error: {e}"))?;
    let payload = Sha256Hasher::hash(&preimage_bytes);

    let sig_bytes = signer
        .sign(&payload)
        .map_err(|e| format!("signing error: {e}"))?;

    // Verify the produced signature matches the payload (mirrors JS SDK behaviour).
    if !verify(&payload, &sig_bytes, &signer.raw_pubkey()) {
        return Err("signature verification failed".to_string());
    }

    let signed_creds = SorobanAddressCredentials {
        address: credentials.address,
        nonce: credentials.nonce,
        signature_expiration_ledger: valid_until_ledger_seq,
        signature: build_signature_scval(signer.raw_pubkey(), &sig_bytes),
    };

    let new_creds = if output_v2 {
        SorobanCredentials::AddressV2(signed_creds)
    } else {
        SorobanCredentials::Address(signed_creds)
    };

    Ok(SorobanAuthorizationEntry {
        credentials: new_creds,
        root_invocation: entry.root_invocation,
    })
}

/// Build a Soroban-compatible signature `ScVal` in the format expected by the default
/// account contract: `[{public_key: ScBytes, signature: ScBytes}]`.
fn build_signature_scval(public_key: [u8; 32], sig: &[u8]) -> ScVal {
    let inner_map = ScMap(
        vec![
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol(StringM::from_str("public_key").unwrap())),
                val: ScVal::Bytes(ScBytes(public_key.to_vec().try_into().unwrap())),
            },
            ScMapEntry {
                key: ScVal::Symbol(ScSymbol(StringM::from_str("signature").unwrap())),
                val: ScVal::Bytes(ScBytes(sig.to_vec().try_into().unwrap())),
            },
        ]
        .try_into()
        .unwrap(),
    );

    ScVal::Vec(Some(
        vec![ScVal::Map(Some(inner_map))].try_into().unwrap(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{NetworkPassphrase, Networks};
    use crate::xdr::{
        ContractId, Hash, InvokeContractArgs, ScAddress, ScSymbol, SorobanAuthorizedFunction,
        SorobanAuthorizedInvocation,
    };

    fn make_address_entry(address: ScAddress) -> SorobanAuthorizationEntry {
        SorobanAuthorizationEntry {
            credentials: SorobanCredentials::Address(SorobanAddressCredentials {
                address,
                nonce: 42,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                    contract_address: ScAddress::Contract(ContractId(Hash([1u8; 32]))),
                    function_name: ScSymbol(StringM::from_str("hello").unwrap()),
                    args: VecM::default(),
                }),
                sub_invocations: VecM::default(),
            },
        }
    }

    #[test]
    fn authorize_entry_v1_produces_address_credentials() {
        let kp = Keypair::random().unwrap();
        let address = ScAddress::Account(crate::xdr::AccountId(
            crate::xdr::PublicKey::PublicKeyTypeEd25519(Uint256(kp.raw_pubkey())),
        ));
        let entry = make_address_entry(address);

        let result = authorize_entry(AuthorizeEntryParams {
            entry,
            signer: &kp,
            valid_until_ledger_seq: 1000,
            network_passphrase: Networks::testnet(),
            use_address_v2: false,
        })
        .unwrap();

        assert!(matches!(result.credentials, SorobanCredentials::Address(_)));
        if let SorobanCredentials::Address(c) = result.credentials {
            assert_eq!(c.signature_expiration_ledger, 1000);
            assert_ne!(c.signature, ScVal::Void);
        }
    }

    #[test]
    fn authorize_entry_v2_produces_address_v2_credentials() {
        let kp = Keypair::random().unwrap();
        let address = ScAddress::Account(crate::xdr::AccountId(
            crate::xdr::PublicKey::PublicKeyTypeEd25519(Uint256(kp.raw_pubkey())),
        ));
        let entry = make_address_entry(address);

        let result = authorize_entry(AuthorizeEntryParams {
            entry,
            signer: &kp,
            valid_until_ledger_seq: 2000,
            network_passphrase: Networks::testnet(),
            use_address_v2: true,
        })
        .unwrap();

        assert!(matches!(
            result.credentials,
            SorobanCredentials::AddressV2(_)
        ));
        if let SorobanCredentials::AddressV2(c) = result.credentials {
            assert_eq!(c.signature_expiration_ledger, 2000);
            assert_ne!(c.signature, ScVal::Void);
        }
    }

    #[test]
    fn incoming_v2_entry_stays_v2_even_when_flag_false() {
        let kp = Keypair::random().unwrap();
        let address = ScAddress::Account(crate::xdr::AccountId(
            crate::xdr::PublicKey::PublicKeyTypeEd25519(Uint256(kp.raw_pubkey())),
        ));
        let entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::AddressV2(SorobanAddressCredentials {
                address,
                nonce: 7,
                signature_expiration_ledger: 0,
                signature: ScVal::Void,
            }),
            root_invocation: SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                    contract_address: ScAddress::Contract(ContractId(Hash([3u8; 32]))),
                    function_name: ScSymbol(StringM::from_str("fn").unwrap()),
                    args: VecM::default(),
                }),
                sub_invocations: VecM::default(),
            },
        };

        let result = authorize_entry(AuthorizeEntryParams {
            entry,
            signer: &kp,
            valid_until_ledger_seq: 500,
            network_passphrase: Networks::testnet(),
            use_address_v2: false, // flag is false, but incoming is V2 — should stay V2
        })
        .unwrap();

        assert!(matches!(
            result.credentials,
            SorobanCredentials::AddressV2(_)
        ));
    }

    #[test]
    fn source_account_entry_passes_through_unchanged() {
        let kp = Keypair::random().unwrap();
        let entry = SorobanAuthorizationEntry {
            credentials: SorobanCredentials::SourceAccount,
            root_invocation: SorobanAuthorizedInvocation {
                function: SorobanAuthorizedFunction::ContractFn(InvokeContractArgs {
                    contract_address: ScAddress::Contract(ContractId(Hash([2u8; 32]))),
                    function_name: ScSymbol(StringM::from_str("noop").unwrap()),
                    args: VecM::default(),
                }),
                sub_invocations: VecM::default(),
            },
        };

        let result = authorize_entry(AuthorizeEntryParams {
            entry,
            signer: &kp,
            valid_until_ledger_seq: 999,
            network_passphrase: Networks::testnet(),
            use_address_v2: false,
        })
        .unwrap();

        assert!(matches!(
            result.credentials,
            SorobanCredentials::SourceAccount
        ));
    }
}
