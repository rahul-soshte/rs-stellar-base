use std::str::FromStr;

use crate::xdr;
use stellar_strkey::{ed25519::PublicKey, Contract, Strkey};

use crate::hashing::{self, HashingBehavior};

pub enum AddressType {
    Account,
    Contract,
}

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

    /// Creates a new contract Address object from a buffer of raw bytes.
    fn contract(buffer: &[u8]) -> Result<Self, &'static str>
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
            Ok(Strkey::PublicKeyEd25519(public_key)) => (
                AddressType::Account,
                public_key.to_string().as_bytes().to_vec(),
            ),
            Ok(Strkey::Contract(contract)) => (AddressType::Contract, contract.0.to_vec()),
            Ok(Strkey::MuxedAccountEd25519(x)) => {
                return Err("Unsupported address type MuxedAccount")
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
                let public_key = account_id.0.clone();
                let xdr::PublicKey::PublicKeyTypeEd25519(m) = public_key;

                Self::account(&m.0)
            }
            xdr::ScAddress::Contract(hash) => Self::contract(&hash.0.0),
            _ => panic!("TODO: Handle all edge cases")
        }
    }

    fn to_string(&self) -> String {
        match &self.address_type {
            AddressType::Account => Strkey::PublicKeyEd25519(
                PublicKey::from_string(
                    &String::from_utf8(self.key.clone()).expect("Invalid UTF-8 sequence"),
                )
                .unwrap(),
            )
            .to_string(),
            AddressType::Contract => {
                //
                let id = self.key.last_chunk::<32>().expect("Not a 32 bytes id");
                Strkey::Contract(Contract(*id)).to_string()
            }
        }
    }

    fn to_sc_val(&self) -> Result<xdr::ScVal, &'static str> {
        Ok(xdr::ScVal::Address(self.to_sc_address().unwrap()))
    }

    fn to_sc_address(&self) -> Result<xdr::ScAddress, &'static str> {
        match &self.address_type {
            AddressType::Account => {
                let inner_uin256 = hex::encode(self.key.clone());
                let original = String::from_utf8(self.key.clone()).unwrap();
                Ok(xdr::ScAddress::Account(
                    xdr::AccountId::from_str(&original).unwrap(),
                ))
            }

            AddressType::Contract => {
                let original = self.key.last_chunk::<32>().unwrap();
                Ok(xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash(*original))))
            }
            _ => Err("Unsupported type"),
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
    fn test_muxed_account_creation_fails() {
        const MUXED_ADDRESS: &str =
            "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK";

        // In Rust, this is typically done by checking for a specific error type or message
        let result = Address::new(MUXED_ADDRESS);
        assert!(result.is_err(), "Should fail for muxed account address");

        // Optionally, you can check the specific error message
        match result {
            Err(error_msg) => {
                assert!(
                    error_msg.contains("MuxedAccount"),
                    "Error should mention MuxedAccount"
                );
            }
            _ => panic!("Should have failed for muxed account address"),
        }
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
                assert!(true)
            }
            xdr::ScAddress::Contract(_) => {
                panic!("Expected ScAddress to be an Account type")
            },
            _ => panic!("not implemented yet") // TODO: Work on all possible type matches.
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
                assert!(true)
            }
            _ => panic!("Expected ScAddress::Contract"),
        }
    }

    #[test]
    fn test_to_sc_val() {
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
    fn test_to_buffer_for_account() {
        // Create an Address instance for an account
        let address = Address::new(ACCOUNT).expect("Failed to create Address");

        // Convert the Address to raw public key bytes
        let buffer = address.to_buffer();

        // Decode the expected bytes using stellar_strkey
        let expected = match Strkey::from_string(ACCOUNT).expect("Invalid ACCOUNT address") {
            Strkey::PublicKeyEd25519(public_key) => public_key.to_string().as_bytes().to_vec(),
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
}
