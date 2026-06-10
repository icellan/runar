//! Thin CLI: reads a hex-script file from argv[1] and writes the analyzer
//! JSON report to stdout. Used by `tools/analyzer-runner/rust.sh`.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::process::ExitCode;

use runar_lang::analyzer::{analyze_script, serialize_report};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: runar_analyzer <hex-file>");
        return ExitCode::from(2);
    }
    let path = &args[1];
    let hex = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("failed to read {}: {}", path, e);
            return ExitCode::from(2);
        }
    };
    let trimmed = hex.trim();
    let result = match analyze_script(trimmed) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("analyzer error: {}", e);
            return ExitCode::from(2);
        }
    };
    let out = serialize_report(&result);
    if let Err(e) = io::stdout().write_all(out.as_bytes()) {
        eprintln!("write error: {}", e);
        return ExitCode::from(2);
    }
    ExitCode::SUCCESS
}
