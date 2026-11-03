use std::str::FromStr;

use crate::xdr;
use stellar_strkey::{
    ed25519::{self, MuxedAccount, PublicKey},
    Contract, MuxedContract, Strkey,
};

use crate::hashing::{self, HashingBehavior};

#[derive(Debug, PartialEq, Eq)]
pub enum AddressType {
    Account,
    Contract,
    MuxedAccount,
    MuxedContract,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Address {
    address_type: AddressType,
    key: Vec<u8>,
}

pub trait AddressTrait {
    /// Creates a new Address instance from a string representation.
    fn new(address: &str) -> Result<Self, &'static str>
    where
        Self: Sized;

    /// Parses a string and returns an Address object.
    fn from_string(address: &str) -> Result<Self, &'static str>
    where
        Self: Sized;

    /// Creates a new account Address object from a buffer of raw bytes.
    fn account(buffer: &[u8]) -> Result<Self, &'static str>
    where
        Self: Sized;

    fn muxed_account(buffer: &[u8]) -> Result<Self, &'static str>
    where
        Self: Sized;

    /// Creates a new contract Address object from a buffer of raw bytes.
    fn contract(buffer: &[u8]) -> Result<Self, &'static str>
    where
        Self: Sized;

    /// Creates a muxed contract from its contract ID followed by a big-endian u64 ID.
    fn muxed_contract(buffer: &[u8]) -> Result<Self, &'static str>
    where
        Self: Sized;

    /// Convert from an xdr.ScVal type.
    fn from_sc_val(sc_val: &xdr::ScVal) -> Result<Self, &'static str>
    where
        Self: Sized;

    /// Convert from an xdr.ScAddress type.
    fn from_sc_address(sc_address: &xdr::ScAddress) -> Result<Self, &'static str>
    where
        Self: Sized;

    /// Serialize an address to string.
    fn to_string(&self) -> String;

    /// Convert the Address to an xdr.ScVal type.
    fn to_sc_val(&self) -> Result<xdr::ScVal, &'static str>;

    /// Convert the Address to an xdr.ScAddress type.
    fn to_sc_address(&self) -> Result<xdr::ScAddress, &'static str>;

    /// Return the raw public key bytes for this address.
    fn to_buffer(&self) -> Vec<u8>;
}

impl AddressTrait for Address {
    fn new(address: &str) -> Result<Self, &'static str>
    where
        Self: Sized,
    {
        let value = match stellar_strkey::Strkey::from_string(address) {
            Ok(Strkey::PublicKeyEd25519(public_key)) => {
                (AddressType::Account, public_key.0.to_vec())
            }
            Ok(Strkey::Contract(contract)) => (AddressType::Contract, contract.0.to_vec()),
            Ok(Strkey::MuxedAccountEd25519(x)) => {
                let mut payload: [u8; 40] = [0; 40];
                let (ed25519, id) = payload.split_at_mut(32);
                ed25519.copy_from_slice(&x.ed25519);
                id.copy_from_slice(&x.id.to_be_bytes());
                (AddressType::MuxedAccount, payload.to_vec())
            }
            Ok(Strkey::MuxedContract(x)) => {
                let mut payload = x.contract_id.to_vec();
                payload.extend_from_slice(&x.id.to_be_bytes());
                (AddressType::MuxedContract, payload)
            }

            _ => return Err("Unsupported address type"),
        };

        Ok(Self {
            address_type: value.0,
            key: value.1,
        })
    }
    fn from_string(address: &str) -> Result<Self, &'static str>
    where
        Self: Sized,
    {
        Self::new(address)
    }

    fn account(buffer: &[u8]) -> Result<Self, &'static str>
    where
        Self: Sized,
    {
        let acc = Strkey::PublicKeyEd25519(PublicKey::from_payload(buffer).unwrap()).to_string();
        Self::new(&acc)
    }

    fn muxed_account(buffer: &[u8]) -> Result<Self, &'static str>
    where
        Self: Sized,
    {
        let acc =
            Strkey::MuxedAccountEd25519(MuxedAccount::from_payload(buffer).unwrap()).to_string();
        Self::new(&acc)
    }

    fn contract(buffer: &[u8]) -> Result<Self, &'static str>
    where
        Self: Sized,
    {
        Self::new(
            &Strkey::Contract(Contract(
                buffer.try_into().expect("Slice is not 32 bytes long"),
            ))
            .to_string(),
        )
    }

    fn muxed_contract(buffer: &[u8]) -> Result<Self, &'static str> {
        let payload: &[u8; 40] = buffer
            .try_into()
            .map_err(|_| "Invalid muxed contract payload")?;
        let contract_id = payload[..32].try_into().unwrap();
        let id = u64::from_be_bytes(payload[32..].try_into().unwrap());
        Self::new(&MuxedContract { contract_id, id }.to_string())
    }

    fn from_sc_val(sc_val: &xdr::ScVal) -> Result<Self, &'static str>
    where
        Self: Sized,
    {
        let address_sc_val = match sc_val {
            xdr::ScVal::Address(sc_address) => sc_address,
            _ => panic!("Invalid Type"),
        };
        Self::from_sc_address(address_sc_val)
    }

    fn from_sc_address(sc_address: &xdr::ScAddress) -> Result<Self, &'static str>
    where
        Self: Sized,
    {
        match sc_address {
            xdr::ScAddress::Account(account_id) => {
                let xdr::PublicKey::PublicKeyTypeEd25519(m) = &account_id.0;

                Self::account(&m.0)
            }
            xdr::ScAddress::Contract(xdr::ContractId(hash)) => Self::contract(&hash.0),
            xdr::ScAddress::MuxedAccount(xdr::MuxedEd25519Account {
                id,
                ed25519: xdr::Uint256(edkey),
            }) => {
                let mut payload: [u8; 40] = [0; 40];
                let (key, keyid) = payload.split_at_mut(32);
                key.copy_from_slice(edkey);
                keyid.copy_from_slice(&id.to_be_bytes());
                Self::muxed_account(&payload)
            }
            xdr::ScAddress::MuxedContract(xdr::MuxedContract { id, contract_id }) => {
                let mut payload = contract_id.0 .0.to_vec();
                payload.extend_from_slice(&id.to_be_bytes());
                Self::muxed_contract(&payload)
            }
            _ => Err("Address type not supported"),
        }
    }

    fn to_string(&self) -> String {
        match &self.address_type {
            AddressType::Account => Strkey::PublicKeyEd25519(PublicKey(
                *self
                    .key
                    .last_chunk::<32>()
                    .expect("Public key is less than 32 bytes"),
            ))
            .to_string()
            .as_str()
            .to_owned(),
            AddressType::Contract => {
                let id = self
                    .key
                    .last_chunk::<32>()
                    .expect("Contract key is less than 32 bytes");
                format!("{}", Strkey::Contract(Contract(*id)))
            }
            AddressType::MuxedAccount => {
                //

                let (ed25519, id) = self.key.split_at(32);
                let id = u64::from_be_bytes(
                    *id.last_chunk::<8>()
                        .expect("Muxed account id is less than 8 bytes"),
                );
                let ed25519 = *ed25519
                    .last_chunk::<32>()
                    .expect("Muxed account key is less than 32 bytes");

                format!(
                    "{}",
                    Strkey::MuxedAccountEd25519(MuxedAccount { id, ed25519 })
                )
            }
            AddressType::MuxedContract => {
                let contract_id = self.key[..32].try_into().unwrap();
                let id = u64::from_be_bytes(self.key[32..].try_into().unwrap());
                format!("{}", MuxedContract { contract_id, id })
            }
        }
    }

    fn to_sc_val(&self) -> Result<xdr::ScVal, &'static str> {
        Ok(xdr::ScVal::Address(self.to_sc_address().unwrap()))
    }

    fn to_sc_address(&self) -> Result<xdr::ScAddress, &'static str> {
        match &self.address_type {
            AddressType::Account => {
                let k = *self.key.last_chunk::<32>().expect("");
                Ok(xdr::ScAddress::Account(xdr::AccountId(
                    xdr::PublicKey::PublicKeyTypeEd25519(xdr::Uint256(k)),
                )))
            }

            AddressType::Contract => {
                let original = self.key.last_chunk::<32>().unwrap();
                Ok(xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash(
                    *original,
                ))))
            }
            AddressType::MuxedAccount => {
                let (ed25519, id) = self.key.split_at(32);
                let id = u64::from_be_bytes(
                    *id.last_chunk::<8>()
                        .expect("Muxed account id is less than 8 bytes"),
                );
                let ed25519 = *ed25519
                    .last_chunk::<32>()
                    .expect("Muxed account key is less than 32 bytes");

                Ok(xdr::ScAddress::MuxedAccount(xdr::MuxedEd25519Account {
                    id,
                    ed25519: xdr::Uint256(ed25519),
                }))
            }
            AddressType::MuxedContract => {
                let contract_id = xdr::ContractId(xdr::Hash(self.key[..32].try_into().unwrap()));
                let id = u64::from_be_bytes(self.key[32..].try_into().unwrap());
                Ok(xdr::ScAddress::MuxedContract(xdr::MuxedContract {
                    id,
                    contract_id,
                }))
            }
        }
    }

    fn to_buffer(&self) -> Vec<u8> {
        self.key.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    const ACCOUNT: &str = "GBBM6BKZPEHWYO3E3YKREDPQXMS4VK35YLNU7NFBRI26RAN7GI5POFBB";
    const CONTRACT: &str = "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE";
    const MUXED_ADDRESS: &str =
        "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK";

    #[test]
    fn test_muxed_contract_address() {
        // SEP-23 vectors: zero and an unsigned ID above i64::MAX.
        for (encoded, id) in [
            (
                "WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJUAAAAAAAAAAAAAWWC",
                0,
            ),
            (
                "WA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAACWJY",
                1_u64 << 63,
            ),
        ] {
            let address = Address::new(encoded).unwrap();
            let expected = xdr::ScAddress::MuxedContract(xdr::MuxedContract {
                id,
                contract_id: xdr::ContractId(xdr::Hash(
                    hex::decode("3f0c34bf93ad0d9971d04ccc90f705511c838aad9734a4a2fb0d7a03fc7fe89a")
                        .unwrap()
                        .try_into()
                        .unwrap(),
                )),
            });
            assert_eq!(address.to_string(), encoded);
            assert_eq!(address.to_sc_address().unwrap(), expected);
            assert_eq!(
                Address::from_sc_val(&xdr::ScVal::Address(expected)).unwrap(),
                address
            );
            assert_eq!(
                Address::muxed_contract(&address.to_buffer()).unwrap(),
                address
            );
        }
    }

    #[test]
    fn test_muxed_contract_invalid_buffer() {
        assert!(Address::muxed_contract(&[0; 39]).is_err());
    }

    #[test]
    fn test_invalid_address_creation() {
        let result = Address::new("GBBB");
        assert!(result.is_err(), "Should fail for invalid address");
    }

    #[test]
    fn test_account_address_creation() {
        let account = Address::new(ACCOUNT).expect("Should create account address");
        assert_eq!(account.to_string(), ACCOUNT);
    }

    #[test]
    fn test_contract_address_creation() {
        let contract = Address::new(CONTRACT).expect("Should create contract address");
        assert_eq!(contract.to_string(), CONTRACT);
    }

    #[test]
    fn test_muxed_account_creation() {
        const MUXED_ADDRESS: &str =
            "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK";

        let result = Address::new(MUXED_ADDRESS).expect("Should create a muxed account address");
        assert_eq!(result.to_string(), MUXED_ADDRESS);
    }

    #[test]
    fn test_from_string() {
        let account_address = "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF";
        let address = Address::from_string(account_address).unwrap();
        assert_eq!(address.to_string(), account_address);
    }

    #[test]
    fn test_account_from_buffer() {
        let zero_buffer = vec![0; 32];
        let address = Address::account(&zero_buffer).unwrap();
        assert_eq!(
            address.to_string(),
            "GAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAWHF"
        );
    }

    #[test]
    fn test_contract_from_buffer() {
        let zero_buffer = vec![0; 32];
        let address = Address::contract(&zero_buffer).unwrap();
        assert_eq!(
            address.to_string(),
            "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABSC4"
        );
    }

    #[test]
    fn creates_address_object_for_accounts() {
        let sc_address = xdr::ScAddress::from_str(ACCOUNT).unwrap();

        // Convert ScAddress to Address
        let account =
            Address::from_sc_address(&sc_address).expect("Failed to create Address from ScAddress");

        // Verify the string representation matches the original account
        assert_eq!(account.to_string(), ACCOUNT);
    }

    #[test]
    fn creates_address_object_for_contracts() {
        // Decode the contract address
        let contract = Contract::from_string(CONTRACT).expect("Failed to decode contract address");

        // Create ScAddress for contract
        let sc_address = xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash(contract.0)));

        // Convert ScAddress to Address
        let contract_address =
            Address::from_sc_address(&sc_address).expect("Failed to create Address from ScAddress");

        // Verify the string representation matches the original contract address
        assert_eq!(contract_address.to_string(), CONTRACT);
    }
    #[test]
    fn creates_address_object_for_muxedaccounts() {
        let sc_address = xdr::ScAddress::from_str(MUXED_ADDRESS).unwrap();

        // Convert ScAddress to Address
        let account =
            Address::from_sc_address(&sc_address).expect("Failed to create Address from ScAddress");

        // Verify the string representation matches the original account
        assert_eq!(account.to_string(), MUXED_ADDRESS);
    }

    #[test]
    fn creates_address_object_for_accounts_sc_address() {
        // Decode the account public key

        let val = xdr::ScAddress::Account(xdr::AccountId::from_str(ACCOUNT).unwrap());
        // Create ScVal with an account address
        let sc_val = xdr::ScVal::Address(val);

        // Convert ScVal to Address
        let account = Address::from_sc_val(&sc_val).expect("Failed to create Address from ScVal");

        // Check that the toString() matches the original account
        assert_eq!(account.to_string(), ACCOUNT);
    }

    #[test]
    fn converts_accounts_to_sc_address() {
        // First, create an Address from the account string
        let address = Address::new(ACCOUNT).expect("Failed to create Address");

        // Convert to ScAddress
        let sc_address = address
            .to_sc_address()
            .expect("Failed to convert to ScAddress");

        // Check that the ScAddress is of the correct type
        match sc_address {
            xdr::ScAddress::Account(_) => {
                // Test passes if it's an Account type
            }
            _ => {
                panic!("Expected ScAddress to be an Account type")
            }
        }

        // To make this more similar to the JS test, we can also check the explicit type
        match sc_address {
            xdr::ScAddress::Account(_) => {
                assert_eq!(sc_address.discriminant(), xdr::ScAddressType::Account);
            }
            _ => panic!("Expected Account type ScAddress"),
        }
    }

    #[test]
    fn test_contract_to_sc_address() {
        // Create an Address from the contract address
        let address = Address::new(CONTRACT).expect("Failed to create Address");

        // Convert to ScAddress
        let sc_address = address
            .to_sc_address()
            .expect("Failed to convert to ScAddress");

        // Check that it's a contract type ScAddress
        match sc_address {
            xdr::ScAddress::Contract(_) => {
                // Test passes if it's a Contract type
            }
            _ => panic!("Expected ScAddress::Contract"),
        }
    }

    #[test]
    fn test_to_sc_val_for_account() {
        // Create an Address instance
        let address = Address::new(ACCOUNT).expect("Failed to create Address");

        // Convert the Address to ScVal
        let sc_val = address.to_sc_val().expect("Failed to convert to ScVal");

        // Ensure the ScVal is an Address type
        match sc_val {
            xdr::ScVal::Address(ref sc_address) => {
                // Convert the Address to ScAddress and compare
                let expected_sc_address = address
                    .to_sc_address()
                    .expect("Failed to convert to ScAddress");
                assert_eq!(sc_address, &expected_sc_address, "ScAddress mismatch");
            }
            _ => panic!("ScVal is not an Address"),
        }
    }
    #[test]
    fn test_to_sc_val_for_contract() {
        // Create an Address instance
        let address = Address::new(CONTRACT).expect("Failed to create Address");

        // Convert the Address to ScVal
        let sc_val = address.to_sc_val().expect("Failed to convert to ScVal");

        // Ensure the ScVal is an Address type
        match sc_val {
            xdr::ScVal::Address(ref sc_address) => {
                // Convert the Address to ScAddress and compare
                let expected_sc_address = address
                    .to_sc_address()
                    .expect("Failed to convert to ScAddress");
                assert_eq!(sc_address, &expected_sc_address, "ScAddress mismatch");
            }
            _ => panic!("ScVal is not an Address"),
        }
    }
    #[test]
    fn test_to_sc_val_for_muxedaccount() {
        // Create an Address instance
        let address = Address::new(MUXED_ADDRESS).expect("Failed to create Address");

        // Convert the Address to ScVal
        let sc_val = address.to_sc_val().expect("Failed to convert to ScVal");

        // Ensure the ScVal is an Address type
        match sc_val {
            xdr::ScVal::Address(ref sc_address) => {
                // Convert the Address to ScAddress and compare
                let expected_sc_address = address
                    .to_sc_address()
                    .expect("Failed to convert to ScAddress");
                assert_eq!(sc_address, &expected_sc_address, "ScAddress mismatch");
            }
            _ => panic!("ScVal is not an Address"),
        }
    }

    #[test]
    fn test_to_buffer_for_account() {
        // Create an Address instance for an account
        let address = Address::new(ACCOUNT).expect("Failed to create Address");

        // Convert the Address to raw public key bytes
        let buffer = address.to_buffer();

        // Decode the expected bytes using stellar_strkey
        let expected = match Strkey::from_string(ACCOUNT).expect("Invalid ACCOUNT address") {
            Strkey::PublicKeyEd25519(PublicKey(k)) => k.to_vec(),
            _ => panic!("Expected an Ed25519 public key"),
        };

        // Compare the buffers
        assert_eq!(buffer, expected, "Buffer for account does not match");
    }

    #[test]
    fn test_to_buffer_for_contract() {
        // Create an Address instance for a contract
        let address = Address::new(CONTRACT).expect("Failed to create Address");

        // Convert the Address to raw contract key bytes
        let buffer = address.to_buffer();

        // Decode the expected bytes using stellar_strkey
        let expected = match Strkey::from_string(CONTRACT).expect("Invalid CONTRACT address") {
            Strkey::Contract(contract) => contract.0.to_vec(),
            _ => panic!("Expected a contract key"),
        };

        // Compare the buffers
        assert_eq!(buffer, expected, "Buffer for contract does not match");
    }
    #[test]
    fn test_to_buffer_for_muxedaccount() {
        // Create an Address instance for an account
        let address = Address::new(MUXED_ADDRESS).expect("Failed to create Address");

        // Convert the Address to raw public key bytes
        let buffer = address.to_buffer();

        // Decode the expected bytes using stellar_strkey
        let expected =
            match Strkey::from_string(MUXED_ADDRESS).expect("Invalid MUXED ACCOUNT address") {
                Strkey::MuxedAccountEd25519(MuxedAccount { ed25519, id }) => {
                    let mut payload: [u8; 40] = [0; 40];
                    let (key, keyid) = payload.split_at_mut(32);
                    key.copy_from_slice(&ed25519);
                    keyid.copy_from_slice(&id.to_be_bytes());
                    payload
                }
                _ => panic!("Expected an Ed25519 public key"),
            };

        // Compare the buffers
        assert_eq!(buffer, expected, "Buffer for account does not match");
    }
}
