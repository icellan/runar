//! Rúnar Compiler (Rust) — CLI entry point.
//!
//! Supports two modes:
//!   --ir <path>     Compile from ANF IR JSON to Bitcoin Script
//!   --source <path> Compile from .runar.ts source to Bitcoin Script (full pipeline)

use clap::Parser;
use std::path::PathBuf;
use std::process;

/// Rúnar Compiler (Rust implementation)
#[derive(Parser, Debug)]
#[command(name = "runar-compiler-rust")]
#[command(about = "Compile Rúnar contracts to Bitcoin Script")]
struct Args {
    /// Path to ANF IR JSON file
    #[arg(long)]
    ir: Option<PathBuf>,

    /// Path to .runar.ts source file
    #[arg(long)]
    source: Option<PathBuf>,

    /// Output artifact path (default: stdout)
    #[arg(long, short)]
    output: Option<PathBuf>,

    /// Output only the script hex (no artifact JSON)
    #[arg(long)]
    hex: bool,

    /// Output only the script ASM (no artifact JSON)
    #[arg(long)]
    asm: bool,

    /// Output only the ANF IR JSON (requires --source)
    #[arg(long)]
    emit_ir: bool,

    /// Stop after parse + validate; print "parser ok" and exit 0 on success
    /// (requires --source). Used by the conformance runner's --parser-only
    /// universal-frontend coverage check.
    #[arg(long)]
    parse_only: bool,

    /// Disable the ANF constant folding pass
    #[arg(long)]
    disable_constant_folding: bool,
}

fn main() {
    let args = Args::parse();

    let opts = runar_compiler_rust::CompileOptions {
        disable_constant_folding: args.disable_constant_folding,
        ..Default::default()
    };

    if args.ir.is_none() && args.source.is_none() {
        eprintln!("Error: must provide --ir or --source flag.");
        eprintln!();
        eprintln!("Usage:");
        eprintln!("  runar-compiler-rust --ir <path>     Compile from ANF IR JSON");
        eprintln!("  runar-compiler-rust --source <path>  Compile from .runar.ts source");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  --output <path>  Write output to file (default: stdout)");
        eprintln!("  --hex            Output only script hex");
        eprintln!("  --asm            Output only script ASM");
        eprintln!("  --emit-ir        Output only ANF IR JSON (requires --source)");
        process::exit(1);
    }

    // Handle --parse-only: read source, run parse + validate, emit
    // "parser ok" on success or diagnostics + non-zero exit on failure.
    // Used by the universal parser-coverage assertion.
    if args.parse_only {
        let source_path = match &args.source {
            Some(p) => p,
            None => {
                eprintln!("--parse-only requires --source");
                process::exit(1);
            }
        };
        let source = match std::fs::read_to_string(source_path) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("read source: {}", e);
                process::exit(1);
            }
        };
        let file_name_str = source_path.to_string_lossy();
        let (errors, warnings) = runar_compiler_rust::frontend_validate(&source, Some(&file_name_str));
        for w in &warnings {
            eprintln!("warning: {}", w);
        }
        if !errors.is_empty() {
            for e in &errors {
                eprintln!("parse error: {}", e);
            }
            process::exit(1);
        }
        println!("parser ok");
        return;
    }

    // Handle --emit-ir: dump ANF IR JSON and exit
    if args.emit_ir {
        let source_path = match &args.source {
            Some(p) => p,
            None => {
                eprintln!("--emit-ir requires --source");
                process::exit(1);
            }
        };
        match runar_compiler_rust::compile_source_to_ir_with_options(source_path, &opts) {
            Ok(program) => {
                match serde_json::to_string_pretty(&program) {
                    Ok(json) => println!("{}", json),
                    Err(e) => {
                        eprintln!("JSON serialization error: {}", e);
                        process::exit(1);
                    }
                }
                return;
            }
            Err(e) => {
                eprintln!("Compilation error: {}", e);
                process::exit(1);
            }
        }
    }

    let artifact = if let Some(source_path) = args.source {
        match runar_compiler_rust::compile_from_source_with_options(&source_path, &opts) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Compilation error: {}", e);
                process::exit(1);
            }
        }
    } else {
        let ir_path = args.ir.unwrap();
        match runar_compiler_rust::compile_from_ir_with_options(&ir_path, &opts) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Compilation error: {}", e);
                process::exit(1);
            }
        }
    };

    // Determine output content
    let output = if args.hex {
        artifact.script.clone()
    } else if args.asm {
        artifact.asm.clone()
    } else {
        match serde_json::to_string_pretty(&artifact) {
            Ok(json) => json,
            Err(e) => {
                eprintln!("JSON serialization error: {}", e);
                process::exit(1);
            }
        }
    };

    // Write output
    if let Some(output_path) = args.output {
        if let Err(e) = std::fs::write(&output_path, &output) {
            eprintln!("Error writing output: {}", e);
            process::exit(1);
        }
        eprintln!("Output written to {}", output_path.display());
    } else {
        println!("{}", output);
    }
}
