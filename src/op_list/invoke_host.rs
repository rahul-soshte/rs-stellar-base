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
        asset: Asset,
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
}
