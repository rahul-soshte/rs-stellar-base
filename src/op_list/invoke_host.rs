use crate::address::Address;
use crate::asset::Asset;
use crate::keypair::Keypair;
use crate::operation;
use crate::operation::OpAttributes;
use crate::operation::Operation;
use crate::operation::OperationBehavior;
use crate::utils::decode_encode_muxed_account::encode_muxed_account_to_address;
use crate::xdr;
use std::str::FromStr;

impl Operation {
    pub fn invoke_host_function(
        &self,
        func: xdr::HostFunction,
        auth: Option<xdr::VecM<xdr::SorobanAuthorizationEntry>>,
    ) -> Result<xdr::Operation, &'static str> {
        let auth_arr = auth.unwrap_or_default();

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
}

#[cfg(test)]
mod tests {
    use crate::contract::ContractBehavior;
    use crate::contract::Contracts;
    use crate::xdr::WriteXdr;
    use xdr::ScAddress::Contract;

    use super::*;

    #[test]
    fn test_invoke_host_function() {
        let contract_id = "CA3D5KRYM6CB7OWQ6TWYRR3Z4T7GNZLKERYNZGGA5SOAOPIFY6YQGAXE";
        // let contract = Contracts::new(contract_id).expect("Failed to create contract");
        let binding = hex::encode(contract_id);
        let hex_id = binding.as_bytes();
        let mut array = [0u8; 32];
        array.copy_from_slice(&hex_id[0..32]);

        let func = xdr::HostFunction::InvokeContract(xdr::InvokeContractArgs {
            contract_address: xdr::ScAddress::from(Contract(xdr::Hash::from(array))),
            function_name: xdr::ScSymbol::from(xdr::StringM::from_str("hello").unwrap()),
            args: vec![xdr::ScVal::String(xdr::ScString::from(
                xdr::StringM::from_str("world").unwrap(),
            ))]
            .try_into()
            .unwrap(),
        });

        let op = Operation::new(None)
            .invoke_host_function(func, None)
            .unwrap();

        let xdr = op.to_xdr(xdr::Limits::none()).unwrap();
        let obj = Operation::from_xdr_object(op).unwrap();

        match obj.get("type").unwrap() {
            operation::Value::Single(x) => assert_eq!(x, "invokeHostFunction"),
            _ => panic!("Invalid operation"),
        };
    }
}
