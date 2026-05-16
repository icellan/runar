//! `runar-compiler-rust debug` — Bitcoin Script runner.
//!
//! Wraps the `bsv-sdk` crate's `Spend` interpreter (the same upstream used
//! by `packages/runar-rs`'s `ScriptVm`). The Rust tier is execute-only —
//! `Spend`'s execution state (stack, alt-stack, program-counter, context)
//! is `pub(crate)`, so per-opcode stepping is not observable from a
//! downstream crate. This is the same documented divergence as the
//! library-level `ScriptVm`. See
//! `packages/runar-rs/src/sdk/script_vm.rs` and the cross-language audit
//! GAP-M2 for context.
//!
//! Usage:
//!
//!   runar-compiler-rust debug --script <hex> [--unlock <hex>]
//!   runar-compiler-rust debug --artifact <path> [--unlock <hex>]
//!
//! G-6 (audits/cross-language-completeness-20260514.md §5.1).

use std::fs;
use std::path::PathBuf;

use bsv::script::locking_script::LockingScript;
use bsv::script::spend::{Spend, SpendParams};
use bsv::script::unlocking_script::UnlockingScript;
use serde::Deserialize;

#[derive(Debug, Default)]
struct DebugArgs {
    script_hex: Option<String>,
    unlock_hex: String,
    artifact: Option<PathBuf>,
}

#[derive(Deserialize)]
struct ArtifactProbe {
    script: Option<String>,
}

/// Parse the `debug` subcommand's arguments from the slice that follows
/// the subcommand name. Returns a wrapper error on malformed flags; an
/// execution failure is reported via stdout, not as an error.
pub fn run(argv: &[String]) -> Result<(), String> {
    let parsed = parse_args(argv)?;

    // Resolve the locking script hex: either --script direct, or --artifact's
    // `script` field. Mirrors the Go debug subcommand's flag surface.
    let locking_hex = if let Some(s) = parsed.script_hex.clone() {
        s
    } else if let Some(path) = &parsed.artifact {
        let bytes = fs::read(path)
            .map_err(|e| format!("read artifact {}: {}", path.display(), e))?;
        let probe: ArtifactProbe = serde_json::from_slice(&bytes)
            .map_err(|e| format!("parse artifact JSON: {}", e))?;
        probe.script.ok_or_else(|| "artifact has no 'script' field".to_string())?
    } else {
        return Err("--script or --artifact is required".to_string());
    };

    let locking = decode_hex(&locking_hex).map_err(|e| format!("locking hex: {}", e))?;
    let unlocking = decode_hex(&parsed.unlock_hex).map_err(|e| format!("unlock hex: {}", e))?;

    let params = SpendParams {
        locking_script: LockingScript::from_binary(&locking),
        unlocking_script: UnlockingScript::from_binary(&unlocking),
        // Dummy transaction context — sufficient for non-CHECKSIG scripts.
        source_txid: "0".repeat(64),
        source_output_index: 0,
        source_satoshis: 0,
        transaction_version: 1,
        transaction_lock_time: 0,
        transaction_sequence: 0xffff_ffff,
        other_inputs: Vec::new(),
        other_outputs: Vec::new(),
        input_index: 0,
    };
    let mut spend = Spend::new(params);

    // Execute-only: the upstream `Spend` interpreter does not expose its
    // stack/pc between step() calls (pub(crate)), so we cannot print a
    // per-opcode trace from outside the crate. We report the final
    // pass/fail status. See the module docstring for the divergence rationale.
    println!(
        "note: Rust debug is execute-only (upstream Spend state is pub(crate)).",
    );
    println!("      Per-opcode stepping is not observable from a downstream crate.");
    println!("      Use the TypeScript `runar debug` or Go `debug` subcommand for");
    println!("      a step trace; both wrap step-mode SDKs.");

    match spend.validate() {
        Ok(true) => {
            println!("final: pass");
        }
        Ok(false) => {
            println!("final: fail (script evaluated to false)");
        }
        Err(e) => {
            println!("final: fail (interpreter error: {:?})", e);
        }
    }
    Ok(())
}

fn parse_args(argv: &[String]) -> Result<DebugArgs, String> {
    let mut out = DebugArgs::default();
    let mut i = 0;
    while i < argv.len() {
        let arg = &argv[i];
        match arg.as_str() {
            "--script" => {
                i += 1;
                out.script_hex = Some(
                    argv.get(i)
                        .cloned()
                        .ok_or_else(|| "--script requires a value".to_string())?,
                );
            }
            "--unlock" => {
                i += 1;
                out.unlock_hex = argv
                    .get(i)
                    .cloned()
                    .ok_or_else(|| "--unlock requires a value".to_string())?;
            }
            "--artifact" => {
                i += 1;
                out.artifact = Some(PathBuf::from(
                    argv.get(i)
                        .cloned()
                        .ok_or_else(|| "--artifact requires a value".to_string())?,
                ));
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            other => return Err(format!("unrecognized flag: {}", other)),
        }
        i += 1;
    }
    Ok(out)
}

fn print_usage() {
    eprintln!(
        "Usage: runar-compiler-rust debug [--script <hex> | --artifact <path>] [--unlock <hex>]"
    );
    eprintln!();
    eprintln!(
        "Runs a Bitcoin Script via the bsv-sdk Spend interpreter and reports"
    );
    eprintln!(
        "the final pass/fail status. Per-opcode stepping is not available in"
    );
    eprintln!(
        "the Rust tier (upstream state is pub(crate)) — use the TS or Go"
    );
    eprintln!(
        "`debug` subcommand for a step trace."
    );
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    if s.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(s).map_err(|e| format!("invalid hex: {}", e))
}
