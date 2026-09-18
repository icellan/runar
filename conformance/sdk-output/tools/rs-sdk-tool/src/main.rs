use serde::Deserialize;
use std::env;
use std::fs;

use runar_lang::sdk::types::{RunarArtifact, SdkValue};
use runar_lang::sdk::contract::RunarContract;
use runar_lang::sdk::ordinals::Inscription;
use runar_lang::sdk::{
    deploy_with_wallet, DeployWithWalletOptions, WalletActionOutput, WalletActionResult,
    WalletClient, WalletOutput,
};

/// R-062: the smallest BRC-100 wallet that can fund a deploy.
struct StubWallet;

impl WalletClient for StubWallet {
    fn get_public_key(&self, _p: &(u32, &str), _k: &str) -> Result<String, String> {
        Ok("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".to_string())
    }
    fn create_signature(&self, _h: &[u8], _p: &(u32, &str), _k: &str) -> Result<Vec<u8>, String> {
        Ok(vec![0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01])
    }
    fn create_action(
        &self,
        _description: &str,
        _outputs: &[WalletActionOutput],
    ) -> Result<WalletActionResult, String> {
        Ok(WalletActionResult { txid: "ab".repeat(32), tx: None })
    }
    fn list_outputs(&self, _b: &str, _t: &[&str], _l: usize) -> Result<Vec<WalletOutput>, String> {
        Ok(vec![])
    }
}

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

/// R-062: drives the tier's WALLET funding path instead of only building the
/// locking script, so all seven tiers can be asked to agree on accept-vs-refuse
/// for one artifact.
#[derive(Deserialize)]
struct WalletDeployInput {
    satoshis: Option<i64>,
    #[serde(rename = "acknowledgeUnsound")]
    acknowledge_unsound: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct Input {
    artifact: serde_json::Value,
    #[serde(rename = "constructorArgs")]
    constructor_args: Vec<TypedArg>,
    inscription: Option<InscriptionInput>,
    #[serde(rename = "walletDeploy")]
    wallet_deploy: Option<WalletDeployInput>,
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
        // `boolean` is the spelling the compiler's ABI carries; `bool` is
        // the alias some frontends use. Accept both (R-248).
        "bool" | "boolean" => SdkValue::Bool(arg.value == "true"),
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
    // `deploy_with_wallet` takes the artifact by reference (R-062) while the
    // contract takes it by value; keep a copy for the wallet path.
    let artifact_for_wallet = artifact.clone();

    let sdk_args: Vec<SdkValue> = input.constructor_args.iter().map(convert_arg).collect();

    let mut contract = RunarContract::new(artifact, sdk_args);
    if let Some(insc) = input.inscription {
        // N-043: a refused attach is a RESULT, not a crash — exit non-zero with
        // the reason on stderr so the runner can compare the refusal verdict
        // across all seven tiers.
        if let Err(e) = contract.with_inscription(Inscription {
            content_type: insc.content_type,
            data: insc.data,
        }) {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
    if let Some(wd) = input.wallet_deploy {
        // R-062: a refusal is a RESULT, not a crash — exit non-zero with the
        // reason on stderr so the runner can compare the verdict across all
        // seven tiers.
        let opts = DeployWithWalletOptions {
            satoshis: Some(wd.satoshis.unwrap_or(1)),
            description: None,
            acknowledge_unsound: wd.acknowledge_unsound.unwrap_or_default(),
        };
        if let Err(e) = deploy_with_wallet(
            &StubWallet,
            "conformance",
            &contract.get_locking_script(),
            &artifact_for_wallet,
            Some(&opts),
        ) {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }

    print!("{}", contract.get_locking_script());
}
