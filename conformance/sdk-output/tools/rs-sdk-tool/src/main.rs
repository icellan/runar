use serde::Deserialize;
use std::env;
use std::fs;

use runar_lang::sdk::types::{RunarArtifact, SdkValue};
use runar_lang::sdk::contract::RunarContract;
use runar_lang::sdk::ordinals::Inscription;

#[derive(Deserialize)]
struct TypedArg {
    #[serde(rename = "type")]
    arg_type: String,
    value: String,
}

#[derive(Deserialize)]
struct InscriptionInput {
    #[serde(rename = "contentType")]
    content_type: String,
    data: String,
}

#[derive(Deserialize)]
struct Input {
    artifact: serde_json::Value,
    #[serde(rename = "constructorArgs")]
    constructor_args: Vec<TypedArg>,
    inscription: Option<InscriptionInput>,
}

fn convert_arg(arg: &TypedArg) -> SdkValue {
    match arg.arg_type.as_str() {
        "bigint" | "int" => {
            // Try i64 first; fall back to BigInt for values exceeding i64 range
            if let Ok(n) = arg.value.parse::<i64>() {
                SdkValue::Int(n)
            } else {
                let n: num_bigint::BigInt = arg.value.parse().expect("invalid bigint");
                SdkValue::BigInt(n)
            }
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

    let mut contract = RunarContract::new(artifact, sdk_args);
    if let Some(insc) = input.inscription {
        contract.with_inscription(Inscription {
            content_type: insc.content_type,
            data: insc.data,
        });
    }
    print!("{}", contract.get_locking_script());
}
