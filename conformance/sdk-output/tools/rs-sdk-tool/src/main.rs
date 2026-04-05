use serde::Deserialize;
use std::env;
use std::fs;

use runar_lang::sdk::types::{RunarArtifact, SdkValue};
use runar_lang::sdk::contract::RunarContract;

#[derive(Deserialize)]
struct TypedArg {
    #[serde(rename = "type")]
    arg_type: String,
    value: String,
}

#[derive(Deserialize)]
struct Input {
    artifact: serde_json::Value,
    #[serde(rename = "constructorArgs")]
    constructor_args: Vec<TypedArg>,
}

fn convert_arg(arg: &TypedArg) -> SdkValue {
    match arg.arg_type.as_str() {
        "bigint" | "int" => {
            let n: i64 = arg.value.parse().expect("invalid bigint");
            SdkValue::Int(n)
        }
        "bool" => SdkValue::Bool(arg.value == "true"),
        _ => {
            // ByteString, PubKey, Addr, Sig, Ripemd160, Sha256, Point — hex strings
            SdkValue::Bytes(arg.value.clone())
        }
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: rs-sdk-tool <input.json>");
        std::process::exit(1);
    }

    let data = fs::read_to_string(&args[1]).expect("failed to read input file");
    let input: Input = serde_json::from_str(&data).expect("failed to parse JSON");

    let artifact: RunarArtifact =
        serde_json::from_value(input.artifact).expect("failed to parse artifact");

    let sdk_args: Vec<SdkValue> = input.constructor_args.iter().map(convert_arg).collect();

    let contract = RunarContract::new(artifact, sdk_args);
    print!("{}", contract.get_locking_script());
}
