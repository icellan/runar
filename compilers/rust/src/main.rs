//! TSOP Compiler (Rust) — CLI entry point.
//!
//! Supports two modes:
//!   --ir <path>     Compile from ANF IR JSON to Bitcoin Script
//!   --source <path> Compile from .tsop.ts source to Bitcoin Script (full pipeline)

use clap::Parser;
use std::path::PathBuf;
use std::process;

/// TSOP Compiler (Rust implementation)
#[derive(Parser, Debug)]
#[command(name = "tsop-compiler-rust")]
#[command(about = "Compile TSOP contracts to Bitcoin Script")]
struct Args {
    /// Path to ANF IR JSON file
    #[arg(long)]
    ir: Option<PathBuf>,

    /// Path to .tsop.ts source file
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
}

fn main() {
    let args = Args::parse();

    if args.ir.is_none() && args.source.is_none() {
        eprintln!("Error: must provide --ir or --source flag.");
        eprintln!();
        eprintln!("Usage:");
        eprintln!("  tsop-compiler-rust --ir <path>     Compile from ANF IR JSON");
        eprintln!("  tsop-compiler-rust --source <path>  Compile from .tsop.ts source");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  --output <path>  Write output to file (default: stdout)");
        eprintln!("  --hex            Output only script hex");
        eprintln!("  --asm            Output only script ASM");
        eprintln!("  --emit-ir        Output only ANF IR JSON (requires --source)");
        process::exit(1);
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
        match tsop_compiler_rust::compile_source_to_ir(source_path) {
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
        match tsop_compiler_rust::compile_from_source(&source_path) {
            Ok(a) => a,
            Err(e) => {
                eprintln!("Compilation error: {}", e);
                process::exit(1);
            }
        }
    } else {
        let ir_path = args.ir.unwrap();
        match tsop_compiler_rust::compile_from_ir(&ir_path) {
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
