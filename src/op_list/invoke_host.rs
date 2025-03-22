use rand_core::{OsRng, RngCore as _};

use crate::address::{Address, AddressTrait};
use crate::asset::{Asset, AssetBehavior};
use crate::keypair::{Keypair, KeypairBehavior};
use crate::operation;
use crate::operation::Operation;
use crate::utils::decode_encode_muxed_account::encode_muxed_account_to_address;
use crate::xdr;
use std::str::FromStr;

impl Operation {
    /// Invoke a stellar host function
    ///
    /// This is the low level function that requires a `HostFunction`. Helpers functions can
    /// be better suited to your needs:
    /// - [create_contract](Self::create_contract)
    /// - [wrap_asset](Self::wrap_asset)
    /// - [upload_wasm](Self::upload_wasm)
    /// - [invoke_contract](Self::invoke_contract)
    /// - [Contracts::call](crate::contract::ContractBehavior::call)
    pub fn invoke_host_function(
        &self,
        func: xdr::HostFunction,
        auth: Option<Vec<xdr::SorobanAuthorizationEntry>>,
    ) -> Result<xdr::Operation, operation::Error> {
        let auth_arr = auth.unwrap_or_default().try_into().unwrap_or_default();

        let invoke_host_function_op = xdr::InvokeHostFunctionOp {
            host_function: func,
            auth: auth_arr,
        };

        let op_body = xdr::OperationBody::InvokeHostFunction(invoke_host_function_op);

        Ok(xdr::Operation {
            source_account: self.source.clone(),
            body: op_body,
        })
    }

    /// Invokes the contract `method` with its `args`
    pub fn invoke_contract(
        &self,
        contract_id: &str,
        method: &str,
        args: Vec<xdr::ScVal>,
        auth: Option<Vec<xdr::SorobanAuthorizationEntry>>,
    ) -> Result<xdr::Operation, operation::Error> {
        let contract_address = Address::from_string(contract_id)
            .map_err(|_| operation::Error::InvalidField("contract_id".into()))?
            .to_sc_address()
            .map_err(|_| operation::Error::InvalidField("contract_id".into()))?;

        let function_name = xdr::ScSymbol(
            method
                .try_into()
                .map_err(|_| operation::Error::InvalidField("method".into()))?,
        );

        let args = args
            .try_into()
            .map_err(|_| operation::Error::InvalidField("args".into()))?;

        let func = xdr::HostFunction::InvokeContract(xdr::InvokeContractArgs {
            contract_address,
            function_name,
            args,
        });

        self.invoke_host_function(func, auth)
    }

    /// Create a new contract for the `wasm_hash`.
    ///
    /// The `salt` and `deployer` are used to computed the contract_id pre-image of the newly
    /// created contract.
    ///
    /// If the contract has a `__constructor` methods, you can provide the `constructor_args`,
    /// this constructor will be invoked during the contract creation.
    pub fn create_contract(
        &self,
        deployer: &str,
        wasm_hash: [u8; 32],
        salt: Option<[u8; 32]>,
        auth: Option<Vec<xdr::SorobanAuthorizationEntry>>,
        constructor_args: Vec<xdr::ScVal>,
    ) -> Result<xdr::Operation, operation::Error> {
        let salt = match salt {
            Some(s) => xdr::Uint256(s),
            _ => xdr::Uint256(Self::get_salty()),
        };

        let address = Address::from_string(deployer)
            .map_err(|_| operation::Error::InvalidField("deployer".into()))?
            .to_sc_address()
            .map_err(|_| operation::Error::InvalidField("deployer".into()))?;

        let constructor_args: xdr::VecM<xdr::ScVal> = constructor_args
            .try_into()
            .map_err(|_| operation::Error::InvalidField("constructor_args".into()))?;

        let func = xdr::HostFunction::CreateContractV2(xdr::CreateContractArgsV2 {
            contract_id_preimage: xdr::ContractIdPreimage::Address(
                xdr::ContractIdPreimageFromAddress { address, salt },
            ),
            executable: xdr::ContractExecutable::Wasm(xdr::Hash(wasm_hash)),
            constructor_args,
        });

        self.invoke_host_function(func, auth)
    }

    /// Create a Stellar Asset Contract for the [Asset], this wraps a classic Stellar asset in
    /// Soroban.
    pub fn wrap_asset(
        &self,
        asset: &Asset,
        auth: Option<Vec<xdr::SorobanAuthorizationEntry>>,
    ) -> Result<xdr::Operation, operation::Error> {
        let func = xdr::HostFunction::CreateContract(xdr::CreateContractArgs {
            contract_id_preimage: xdr::ContractIdPreimage::Asset(asset.to_xdr_object()),
            executable: xdr::ContractExecutable::StellarAsset,
        });

        self.invoke_host_function(func, auth)
    }

    /// Upload the `wasm` executable.
    ///
    /// The executable can be used to deploy a new contract using
    /// [create_contract](Self::create_contract).
    pub fn upload_wasm(
        &self,
        wasm: &[u8],
        auth: Option<Vec<xdr::SorobanAuthorizationEntry>>,
    ) -> Result<xdr::Operation, operation::Error> {
        let bytes = wasm
            .to_vec()
            .try_into()
            .map_err(|_| operation::Error::InvalidField("wasm".into()))?;
        let func = xdr::HostFunction::UploadContractWasm(bytes);
        self.invoke_host_function(func, auth)
    }

    fn get_salty() -> [u8; 32] {
        let mut salt = [0u8; 32];
        let mut rng = OsRng;
        rng.fill_bytes(&mut salt);
        salt
    }
}

#[cfg(test)]
mod tests {
    use sha2::digest::crypto_common::Key;
    use stellar_strkey::Strkey;

    use crate::contract::ContractBehavior;
    use crate::contract::Contracts;
    use crate::xdr::WriteXdr;

    use super::*;

    #[test]
    fn test_invoke_host_function() {
        let contract_id = "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE";
        let id = if let Strkey::Contract(stellar_strkey::Contract(id)) =
            Strkey::from_str(contract_id).unwrap()
        {
            id
        } else {
            panic!("Fail")
        };

        let func = xdr::HostFunction::InvokeContract(xdr::InvokeContractArgs {
            contract_address: xdr::ScAddress::Contract(xdr::Hash::from(id)),
            function_name: xdr::ScSymbol::from(xdr::StringM::from_str("hello").unwrap()),
            args: vec![xdr::ScVal::String(xdr::ScString::from(
                xdr::StringM::from_str("world").unwrap(),
            ))]
            .try_into()
            .unwrap(),
        });


        let op = Operation::new()
            .invoke_host_function(func.clone(), None)
            .unwrap();

        if let xdr::OperationBody::InvokeHostFunction(f) = op.body {
            assert_eq!(f.host_function, func);
            if let xdr::HostFunction::InvokeContract(xdr::InvokeContractArgs {
                contract_address,
                function_name,
                args,
            }) = f.host_function
            {
                if let xdr::ScAddress::Contract(xdr::Hash(cid)) = contract_address {
                    assert_eq!(cid, id);
                } else {
                    panic!("Fail")
                }
            }
        }
    }

    #[test]
    fn test_invoke_contract() {
        let contract_id = "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE";

        let contract = Contracts::new(contract_id).unwrap();

        let op = Operation::new()
            .invoke_contract(contract_id, "call_me", [].into(), None)
            .unwrap();

        let cop = contract.call("call_me", None);
        assert_eq!(op, cop);

        if let xdr::OperationBody::InvokeHostFunction(xdr::InvokeHostFunctionOp {
            host_function:
                xdr::HostFunction::InvokeContract(xdr::InvokeContractArgs {
                    contract_address,
                    function_name,
                    args,
                }),
            auth,
        }) = op.body
        {
            let exp_contract_address = xdr::ScAddress::from_str(contract_id).unwrap();
            assert_eq!(contract_address, exp_contract_address);

            let exp_fname = xdr::ScSymbol("call_me".try_into().unwrap());
            assert_eq!(function_name, exp_fname);

            return;
        }
        panic!("Fail")
    }

    #[test]
    fn test_invoke_contract_bad_contract_id() {
        let contract_id = "GA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE";

        let op = Operation::new().invoke_contract(contract_id, "call_me", [].into(), None);

        assert_eq!(
            op.err(),
            Some(operation::Error::InvalidField("contract_id".into()))
        );
    }
    #[test]
    fn test_invoke_contract_bad_method() {
        let contract_id = "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE";

        let op = Operation::new().invoke_contract(
            contract_id,
            "call_me_but_this_is_a_too_long_method",
            [].into(),
            None,
        );

        assert_eq!(
            op.err(),
            Some(operation::Error::InvalidField("method".into()))
        );
    }

    #[test]
    fn test_create_contract() {
        let deployer = Keypair::random().unwrap().public_key();
        let wasm_hash = [0; 32];
        let salt = Keypair::random().unwrap().raw_pubkey();
        let op = Operation::new()
            .create_contract(&deployer, wasm_hash, Some(salt), None, [].into())
            .unwrap();

        if let xdr::OperationBody::InvokeHostFunction(xdr::InvokeHostFunctionOp {
            host_function:
                xdr::HostFunction::CreateContractV2(xdr::CreateContractArgsV2 {
                    contract_id_preimage:
                        xdr::ContractIdPreimage::Address(xdr::ContractIdPreimageFromAddress {
                            address,
                            salt: actual_salt,
                        }),
                    executable,
                    constructor_args,
                }),
            auth,
        }) = op.body
        {
            assert_eq!(address, xdr::ScAddress::from_str(&deployer).unwrap());
            assert_eq!(actual_salt, xdr::Uint256(salt));
            assert_eq!(
                executable,
                xdr::ContractExecutable::Wasm(xdr::Hash(wasm_hash))
            );
            //
            return;
        }
        panic!("Fail")
    }
    #[test]
    fn test_create_contract_default_salt() {
        let deployer = Keypair::random().unwrap().public_key();
        let wasm_hash = [0; 32];
        let op = Operation::new()
            .create_contract(&deployer, wasm_hash, None, None, [].into())
            .unwrap();

        if let xdr::OperationBody::InvokeHostFunction(xdr::InvokeHostFunctionOp {
            host_function:
                xdr::HostFunction::CreateContractV2(xdr::CreateContractArgsV2 {
                    contract_id_preimage:
                        xdr::ContractIdPreimage::Address(xdr::ContractIdPreimageFromAddress {
                            address,
                            salt: actual_salt,
                        }),
                    executable,
                    constructor_args,
                }),
            auth,
        }) = op.body
        {
            assert_eq!(address, xdr::ScAddress::from_str(&deployer).unwrap());
            assert_ne!(actual_salt, xdr::Uint256([0; 32]));
            assert_eq!(
                executable,
                xdr::ContractExecutable::Wasm(xdr::Hash(wasm_hash))
            );
            //
            return;
        }
        panic!("Fail")
    }

    #[test]
    fn test_create_contract_bad_deployer() {
        let deployer = Keypair::random().unwrap().public_key().replace("G", "M");
        let wasm_hash = Keypair::random().unwrap().raw_pubkey();
        let op = Operation::new().create_contract(&deployer, wasm_hash, None, None, [].into());

        assert_eq!(
            op.err(),
            Some(operation::Error::InvalidField("deployer".into()))
        );
    }

    #[test]
    fn test_wrap_asset() {
        let native = Asset::native();

        let op = Operation::new().wrap_asset(&native, None).unwrap();
        if let xdr::OperationBody::InvokeHostFunction(xdr::InvokeHostFunctionOp {
            host_function:
                xdr::HostFunction::CreateContract(xdr::CreateContractArgs {
                    contract_id_preimage: xdr::ContractIdPreimage::Asset(asset),
                    executable: xdr::ContractExecutable::StellarAsset,
                }),
            auth,
        }) = op.body
        {
            assert_eq!(native.to_xdr_object(), asset);
            //
            return;
        }
        panic!("Fail")
    }

    #[test]
    fn test_upload_wasm() {
        let wasm = [0; 420];
        let op = Operation::new().upload_wasm(&wasm, None).unwrap();

        if let xdr::OperationBody::InvokeHostFunction(xdr::InvokeHostFunctionOp {
            host_function: xdr::HostFunction::UploadContractWasm(bytes),
            auth,
        }) = op.body
        {
            assert_eq!(bytes.as_slice(), &wasm);
            //
            return;
        }
        panic!("Fail")
    }
}
