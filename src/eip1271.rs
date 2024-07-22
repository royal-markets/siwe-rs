use alloy::{
    contract::{ContractInstance, Error as ContractError, Interface},
    dyn_abi::DynSolValue,
    json_abi::JsonAbi,
};
use alloy::{
    providers::RootProvider,
    transports::http::{Client, Http},
};

use crate::VerificationError;

const METHOD_NAME: &str = "isValidSignature";

pub async fn verify_eip1271(
    address: [u8; 20],
    message_hash: &[u8; 32],
    signature: &[u8],
    provider: &RootProvider<Http<Client>>,
) -> Result<bool, VerificationError> {
    let abi = JsonAbi::parse([
        "function isValidSignature(bytes32 _message, bytes _signature) public view returns (bytes4)",
    ]).unwrap();

    let interface = Interface::new(abi);
    let contract: ContractInstance<_, _, _> = interface.connect(address.into(), provider);

    match contract
        .function(
            METHOD_NAME,
            &[
                DynSolValue::FixedBytes(message_hash.into(), 32),
                DynSolValue::Bytes(signature.to_vec()),
            ],
        )
        .unwrap()
        .call_raw()
        .await
    {
        Ok(bytes) => Ok(**bytes == [22, 38, 186, 126]),
        Err(ContractError::AbiError(_)) => Ok(false),
        Err(e) => Err(VerificationError::ContractCall(e.to_string())),
    }
}
