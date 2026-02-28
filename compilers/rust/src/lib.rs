//! TSOP Compiler (Rust) — library root.
//!
//! Full compilation pipeline:
//!   - IR consumer mode: accepts ANF IR JSON, emits Bitcoin Script.
//!   - Source mode: compiles `.tsop.ts` source files through all passes.

pub mod artifact;
pub mod codegen;
pub mod frontend;
pub mod ir;

use artifact::{assemble_artifact, TSOPArtifact};
use codegen::emit::emit;
use codegen::stack::lower_to_stack;
use ir::loader::{load_ir, load_ir_from_str};

use std::path::Path;

/// Compile from an ANF IR JSON file on disk.
pub fn compile_from_ir(path: &Path) -> Result<TSOPArtifact, String> {
    let program = load_ir(path)?;
    compile_from_program(&program)
}

/// Compile from an ANF IR JSON string.
pub fn compile_from_ir_str(json_str: &str) -> Result<TSOPArtifact, String> {
    let program = load_ir_from_str(json_str)?;
    compile_from_program(&program)
}

/// Compile from a `.tsop.ts` source file on disk.
pub fn compile_from_source(path: &Path) -> Result<TSOPArtifact, String> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| format!("reading source file: {}", e))?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "contract.ts".to_string());
    compile_from_source_str(&source, Some(&file_name))
}

/// Compile from a `.tsop.ts` source string.
pub fn compile_from_source_str(
    source: &str,
    file_name: Option<&str>,
) -> Result<TSOPArtifact, String> {
    // Pass 1: Parse
    let parse_result = frontend::parser::parse(source, file_name);
    if !parse_result.errors.is_empty() {
        let error_msgs: Vec<String> = parse_result.errors.iter().map(|e| e.to_string()).collect();
        return Err(format!("Parse errors:\n  {}", error_msgs.join("\n  ")));
    }

    let contract = parse_result
        .contract
        .ok_or_else(|| "No contract found in source file".to_string())?;

    // Pass 2: Validate
    let validation = frontend::validator::validate(&contract);
    if !validation.errors.is_empty() {
        return Err(format!(
            "Validation errors:\n  {}",
            validation.errors.join("\n  ")
        ));
    }
    for w in &validation.warnings {
        eprintln!("Validation warning: {}", w);
    }

    // Pass 3: Type-check
    let tc_result = frontend::typecheck::typecheck(&contract);
    if !tc_result.errors.is_empty() {
        return Err(format!(
            "Type-check errors:\n  {}",
            tc_result.errors.join("\n  ")
        ));
    }

    // Pass 4: ANF Lower
    let anf_program = frontend::anf_lower::lower_to_anf(&contract);

    // Passes 5-6: Backend (stack lowering + emit)
    compile_from_program(&anf_program)
}

/// Compile from a `.tsop.ts` source file to ANF IR only (passes 1-4).
pub fn compile_source_to_ir(path: &Path) -> Result<ir::ANFProgram, String> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| format!("reading source file: {}", e))?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "contract.ts".to_string());
    compile_source_str_to_ir(&source, Some(&file_name))
}

/// Compile from a `.tsop.ts` source string to ANF IR only (passes 1-4).
pub fn compile_source_str_to_ir(
    source: &str,
    file_name: Option<&str>,
) -> Result<ir::ANFProgram, String> {
    let parse_result = frontend::parser::parse(source, file_name);
    if !parse_result.errors.is_empty() {
        let error_msgs: Vec<String> = parse_result.errors.iter().map(|e| e.to_string()).collect();
        return Err(format!("Parse errors:\n  {}", error_msgs.join("\n  ")));
    }

    let contract = parse_result
        .contract
        .ok_or_else(|| "No contract found in source file".to_string())?;

    let validation = frontend::validator::validate(&contract);
    if !validation.errors.is_empty() {
        return Err(format!(
            "Validation errors:\n  {}",
            validation.errors.join("\n  ")
        ));
    }

    let tc_result = frontend::typecheck::typecheck(&contract);
    if !tc_result.errors.is_empty() {
        return Err(format!(
            "Type-check errors:\n  {}",
            tc_result.errors.join("\n  ")
        ));
    }

    Ok(frontend::anf_lower::lower_to_anf(&contract))
}

/// Compile a parsed ANF program to a TSOP artifact.
pub fn compile_from_program(program: &ir::ANFProgram) -> Result<TSOPArtifact, String> {
    // Pass 5: Stack lowering
    let stack_methods = lower_to_stack(program)?;

    // Peephole optimization is disabled to match the TS reference output exactly.
    // The TS reference compiler does not apply peephole optimizations.

    // Pass 6: Emit
    let emit_result = emit(&stack_methods)?;

    let artifact = assemble_artifact(program, &emit_result.script_hex, &emit_result.script_asm);
    Ok(artifact)
}
