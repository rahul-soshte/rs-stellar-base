use core::str;
use std::str::FromStr;

use crate::address::{Address, AddressTrait};
use crate::xdr;
use stellar_strkey::{Contract, Strkey};

#[derive(Clone, Debug)]
pub struct Contracts {
    id: Vec<u8>,
}

pub trait ContractBehavior {
    /// Creates a new Contract instance from a string representation of the contract ID.
    fn new(contract_id: &str) -> Result<Self, &'static str>
    where
        Self: Sized;

    /// Returns the Stellar contract ID as a string.
    fn contract_id(&self) -> String;

    /// Returns the contract ID as a string (similar to contract_id method).
    fn to_string(&self) -> String;

    /// Returns the wrapped address of this contract.
    fn address(&self) -> Address; // Address type needs to be defined.

    /// Invokes a contract call with the specified method and parameters.
    fn call(&self, method: &str, params: Option<Vec<xdr::ScVal>>) -> xdr::Operation; // Operation and ScVal types need to be defined.

    /// Returns the read-only footprint entries necessary for invocations to this contract.
    fn get_footprint(&self) -> xdr::LedgerKey; // LedgerKey type needs to be defined.
}

// Implement the trait for the Contracts struct
impl ContractBehavior for Contracts {
    fn new(contract_id: &str) -> std::result::Result<Contracts, &'static str> {
        let contract_id = Strkey::Contract(
            Contract::from_str(contract_id).map_err(|_| "Failed to decode contract ID")?,
        );
        Ok(Self {
            id: contract_id.to_string().as_bytes().to_vec(),
        })
    }

    fn call(&self, method: &str, params: Option<Vec<xdr::ScVal>>) -> xdr::Operation {
        xdr::Operation {
            source_account: None,
            body: xdr::OperationBody::InvokeHostFunction(xdr::InvokeHostFunctionOp {
                host_function: xdr::HostFunction::InvokeContract(xdr::InvokeContractArgs {
                    contract_address: xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash(
                        contract_id_strkey(String::from_utf8(self.id.clone()).unwrap().as_str()).0,
                    ))),
                    function_name: xdr::ScSymbol::from(xdr::StringM::from_str(method).unwrap()),
                    args: xdr::VecM::<xdr::ScVal>::try_from(params.unwrap_or_default()).unwrap(),
                }),
                auth: xdr::VecM::<xdr::SorobanAuthorizationEntry>::try_from(Vec::new()).unwrap(),
            }),
        }
    }

    fn contract_id(&self) -> String {
        str::from_utf8(&self.id)
            .map(|s| s.to_string())
            .unwrap_or_else(|_| String::from(""))
    }

    fn to_string(&self) -> String {
        self.contract_id()
    }

    fn address(&self) -> Address {
        //TODO: Simplify this lol, wtf you doin
        Address::contract(
            &contract_id_strkey(String::from_utf8(self.id.clone()).unwrap().as_str()).0,
        )
        .unwrap()
    }

    fn get_footprint(&self) -> xdr::LedgerKey {
        xdr::LedgerKey::ContractData(xdr::LedgerKeyContractData {
            contract: xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash(
                contract_id_strkey(&self.contract_id()).0,
            ))),
            key: xdr::ScVal::LedgerKeyContractInstance,
            durability: xdr::ContractDataDurability::Persistent,
        })
    }
}

pub fn contract_id_strkey(contract_id: &str) -> stellar_strkey::Contract {
    stellar_strkey::Contract::from_string(contract_id).unwrap()
}

#[cfg(test)]
mod tests {
    use xdr::{Limits, OperationBody, WriteXdr};

    use super::*;

    const NULL_ADDRESS: &str = "CAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2KM";

    #[test]
    fn test_contract_constructor() {
        let test_addresses = vec![
            NULL_ADDRESS,
            "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE",
        ];

        for cid in test_addresses {
            let contract = Contracts::new(cid).expect("Failed to create contract");
            assert_eq!(contract.contract_id(), cid);
        }
    }

    #[test]
    fn test_contract_obsolete_hex_id() {
        // Create a string of 63 zeros followed by a 1
        let obsolete_hex_id = "0".repeat(63) + "1";

        // Test that creating a contract with this ID results in an error
        let result = Contracts::new(&obsolete_hex_id);

        // Assert that the result is an error
        assert!(result.is_err(), "Expected an error for obsolete hex ID");
    }

    #[test]
    fn test_contract_invalid_id() {
        // Test with an entirely invalid string
        let invalid_id = "foobar";

        // Test that creating a contract with this ID results in an error
        let result = Contracts::new(invalid_id);

        // Assert that the result is an error
        assert!(result.is_err(), "Expected an error for invalid contract ID");
    }

    #[test]
    fn test_contract_address() {
        // Create a contract using the NULL_ADDRESS
        let contract = Contracts::new(NULL_ADDRESS).expect("Failed to create contract");

        // Get the address and convert to string
        let address_str = contract.address().to_string();

        // Assert that the address string matches the original contract ID
        assert_eq!(
            address_str, NULL_ADDRESS,
            "Contract address should match the original contract ID"
        );
    }

    #[test]
    fn test_get_footprint_includes_correct_contract_ledger_keys() {
        // Create a contract with a NULL_ADDRESS equivalent (all zeros in this case)
        let contract = Contracts::new(NULL_ADDRESS).expect("Failed to create contract");

        // Assert the contract ID is as expected
        assert_eq!(contract.contract_id(), NULL_ADDRESS);

        // Get the actual footprint
        let actual_footprint = contract.get_footprint();

        // Build the expected footprint
        let expected_footprint = xdr::LedgerKey::ContractData(xdr::LedgerKeyContractData {
            contract: xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash(contract_id_strkey(NULL_ADDRESS).0))),
            key: xdr::ScVal::LedgerKeyContractInstance,
            durability: xdr::ContractDataDurability::Persistent,
        });

        // Assert the footprints match
        assert_eq!(actual_footprint, expected_footprint);
    }

    #[test]
    fn test_call_method_with_arguments() {
        // Define a NULL_ADDRESS equivalent
        let contract = Contracts::new(NULL_ADDRESS).expect("Failed to create contract");

        // Method name
        let method = "method";

        // Arguments for the call
        //TODO: Implement native_to_scval
        let arg1 = xdr::ScVal::Symbol(xdr::ScSymbol::from(xdr::StringM::from_str("arg!").unwrap()));
        let arg2 = xdr::ScVal::I32(2);

        // Call the contract
        let operation = contract.call(method, Some(vec![arg1.clone(), arg2.clone()]));

        // Expected contract address
        let expected_contract_address =
            xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash(contract_id_strkey(NULL_ADDRESS).0)));

        // Verify the operation structure
        if let OperationBody::InvokeHostFunction(host_function_op) = operation.body {
            if let xdr::HostFunction::InvokeContract(args) = host_function_op.host_function {
                // Check the contract address
                assert_eq!(args.contract_address, expected_contract_address);

                // Check the function name
                assert_eq!(
                    args.function_name,
                    xdr::ScSymbol::from(xdr::StringM::from_str(method).unwrap())
                );

                // Check the arguments
                assert_eq!(args.args.len(), 2);
                assert_eq!(args.args[0], arg1);
                assert_eq!(args.args[1], arg2);
            } else {
                panic!("Expected InvokeContract host function");
            }
        } else {
            panic!("Expected InvokeHostFunction operation body");
        }
    }

    #[test]
    fn test_call_with_no_parameters() {
        // Define a NULL_ADDRESS equivalent
        let contract = Contracts::new(NULL_ADDRESS).expect("Failed to create contract");

        // Call the contract with a method that takes no parameters
        let operation = contract.call("empty", None);

        // Verify the operation is correctly built
        if let OperationBody::InvokeHostFunction(host_function_op) = operation.clone().body {
            if let xdr::HostFunction::InvokeContract(args) = host_function_op.host_function {
                // Check the function name
                assert_eq!(
                    args.function_name,
                    xdr::ScSymbol::from(xdr::StringM::from_str("empty").unwrap())
                );

                // Check that no parameters are passed
                assert!(args.args.is_empty());
            } else {
                panic!("Expected InvokeContract host function");
            }
        } else {
            panic!("Expected InvokeHostFunction operation body");
        }

        // Serialize to XDR
        let xdr = operation.to_xdr(Limits::none()).unwrap();
        assert!(
            !xdr.is_empty(),
            "XDR serialization should produce a non-empty result"
        );
    }

    #[test]
    fn test_call_builds_valid_xdr() {
        let contract = Contracts::new(NULL_ADDRESS).expect("Failed to create contract");

        // Method and parameters for the call
        let method = "method";
        let arg1 = xdr::ScVal::Symbol(xdr::ScSymbol::from(xdr::StringM::from_str("arg!").unwrap()));
        let arg2 = xdr::ScVal::I32(2);
        let operation = contract.call(method, Some(vec![arg1, arg2]));

        // Serialize to XDR
        let xdr = operation.to_xdr(Limits::none()).unwrap();
        assert!(
            !xdr.is_empty(),
            "XDR serialization should produce a non-empty result"
        );
    }

    #[test]
    fn test_contract_id_as_sc_address() {
        let contract = Contracts::new(NULL_ADDRESS).expect("Failed to create contract");

        // Call the contract
        let operation = contract.call("method", None);

        // Extract the args
        if let OperationBody::InvokeHostFunction(host_function_op) = operation.body {
            if let xdr::HostFunction::InvokeContract(args) = host_function_op.host_function {
                let expected_address =
                    xdr::ScAddress::Contract(xdr::ContractId(xdr::Hash(contract_id_strkey(NULL_ADDRESS).0)));
                assert_eq!(args.contract_address, expected_address);
            } else {
                panic!("Expected InvokeContract host function");
            }
        } else {
            panic!("Expected InvokeHostFunction operation body");
        }
    }

    #[test]
    fn test_method_name_as_second_arg() {
        let contract = Contracts::new(NULL_ADDRESS).expect("Failed to create contract");

        // Call the contract
        let operation = contract.call("method", None);

        // Extract the args
        if let OperationBody::InvokeHostFunction(host_function_op) = operation.body {
            if let xdr::HostFunction::InvokeContract(args) = host_function_op.host_function {
                assert_eq!(
                    args.function_name,
                    xdr::ScSymbol::from(xdr::StringM::from_str("method").unwrap())
                );
            } else {
                panic!("Expected InvokeContract host function");
            }
        } else {
            panic!("Expected InvokeHostFunction operation body");
        }
    }

    #[test]
    fn test_passes_all_params() {
        let contract = Contracts::new(NULL_ADDRESS).expect("Failed to create contract");

        // Method and parameters for the call
        let method = "method";
        let arg1 = xdr::ScVal::Symbol(xdr::ScSymbol::from(xdr::StringM::from_str("arg!").unwrap()));
        let arg2 = xdr::ScVal::I32(2);
        let operation = contract.call(method, Some(vec![arg1.clone(), arg2.clone()]));

        // Extract the args
        if let OperationBody::InvokeHostFunction(host_function_op) = operation.body {
            if let xdr::HostFunction::InvokeContract(args) = host_function_op.host_function {
                assert_eq!(args.args.len(), 2);
                assert_eq!(args.args[0], arg1);
                assert_eq!(args.args[1], arg2);
            } else {
                panic!("Expected InvokeContract host function");
            }
        } else {
            panic!("Expected InvokeHostFunction operation body");
        }
    }
}
