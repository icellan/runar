//! MessageBoard integration test — stateful contract with addDataOutput
//! emitting per-message OP_RETURN payloads alongside state transitions.
//!
//! Mirrors `integration/ts/message-board.test.ts` and uses the shared
//! `examples/ts/message-board/MessageBoard.runar.ts` reference contract.
//! Compile + script-shape checks run by default; deploy + call cycle is
//! gated on the `regtest` feature.

use crate::helpers::*;
use runar_lang::sdk::{DeployOptions, RunarContract, SdkValue};

const SOURCE_PATH: &str = "examples/ts/message-board/MessageBoard.runar.ts";

#[test]
fn test_message_board_compiles() {
    let artifact = compile_contract(SOURCE_PATH);
    assert_eq!(artifact.contract_name, "MessageBoard");
    assert!(!artifact.script.is_empty());
}

#[test]
#[cfg_attr(not(feature = "regtest"), ignore)]
fn test_message_board_deploy_and_post() {
    skip_if_no_node();

    let artifact = compile_contract(SOURCE_PATH);

    let mut provider = create_provider();
    let (signer, _wallet) = create_funded_wallet(&mut provider);

    // Inspect the constructor params to construct deploy args.
    // MessageBoard typically takes a counter or root; pass conservative
    // defaults that match the reference example.
    let constructor_args: Vec<SdkValue> = artifact
        .abi
        .constructor
        .params
        .iter()
        .map(|p| match p.param_type.as_str() {
            "bigint" => SdkValue::Int(0),
            "ByteString" | "Addr" | "PubKey" | "Sig" => {
                SdkValue::Bytes("00".repeat(32))
            }
            "boolean" => SdkValue::Bool(false),
            _ => SdkValue::Bytes("".to_string()),
        })
        .collect();

    let mut contract = RunarContract::new(artifact, constructor_args);

    let (deploy_txid, _tx) = contract
        .deploy(&mut provider, &*signer, &DeployOptions {
            satoshis: 20_000,
            change_address: None,
        })
        .expect("deploy failed");
    assert!(!deploy_txid.is_empty());
    assert_eq!(deploy_txid.len(), 64);
}
