//! Rúnar Compiler (Rust) — library root.
//!
//! Full compilation pipeline:
//!   - IR consumer mode: accepts ANF IR JSON, emits Bitcoin Script.
//!   - Source mode: compiles `.runar.ts` source files through all passes.

pub mod artifact;
pub mod codegen;
pub mod frontend;
pub mod ir;

use artifact::{assemble_artifact, RunarArtifact};
use codegen::emit::emit;
use codegen::optimizer::optimize_stack_ops;
use codegen::stack::lower_to_stack;
use ir::loader::{load_ir, load_ir_from_str};

use std::path::Path;

/// Compile from an ANF IR JSON file on disk.
pub fn compile_from_ir(path: &Path) -> Result<RunarArtifact, String> {
    let program = load_ir(path)?;
    compile_from_program(&program)
}

/// Compile from an ANF IR JSON string.
pub fn compile_from_ir_str(json_str: &str) -> Result<RunarArtifact, String> {
    let program = load_ir_from_str(json_str)?;
    compile_from_program(&program)
}

/// Compile from a `.runar.ts` source file on disk.
pub fn compile_from_source(path: &Path) -> Result<RunarArtifact, String> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| format!("reading source file: {}", e))?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "contract.ts".to_string());
    compile_from_source_str(&source, Some(&file_name))
}

/// Compile from a `.runar.ts` source string.
pub fn compile_from_source_str(
    source: &str,
    file_name: Option<&str>,
) -> Result<RunarArtifact, String> {
    // Pass 1: Parse (auto-selects parser based on file extension)
    let parse_result = frontend::parser::parse_source(source, file_name);
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

    // Pass 4.5: EC optimization
    let anf_program = frontend::anf_optimize::optimize_ec(anf_program);

    // Passes 5-6: Backend (stack lowering + emit)
    compile_from_program(&anf_program)
}

/// Compile from a `.runar.ts` source file to ANF IR only (passes 1-4).
pub fn compile_source_to_ir(path: &Path) -> Result<ir::ANFProgram, String> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| format!("reading source file: {}", e))?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "contract.ts".to_string());
    compile_source_str_to_ir(&source, Some(&file_name))
}

/// Compile from a `.runar.ts` source string to ANF IR only (passes 1-4).
pub fn compile_source_str_to_ir(
    source: &str,
    file_name: Option<&str>,
) -> Result<ir::ANFProgram, String> {
    let parse_result = frontend::parser::parse_source(source, file_name);
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

    let anf_program = frontend::anf_lower::lower_to_anf(&contract);
    Ok(frontend::anf_optimize::optimize_ec(anf_program))
}

/// Compile a parsed ANF program to a Rúnar artifact.
pub fn compile_from_program(program: &ir::ANFProgram) -> Result<RunarArtifact, String> {
    // Pass 4.5: EC optimization (in case we receive unoptimized ANF from IR)
    let optimized = frontend::anf_optimize::optimize_ec(program.clone());

    // Pass 5: Stack lowering
    let mut stack_methods = lower_to_stack(&optimized)?;

    // Peephole optimization — runs on Stack IR before emission.
    for method in &mut stack_methods {
        method.ops = optimize_stack_ops(&method.ops);
    }

    // Pass 6: Emit
    let emit_result = emit(&stack_methods)?;

    let artifact = assemble_artifact(
        &optimized,
        &emit_result.script_hex,
        &emit_result.script_asm,
        emit_result.constructor_slots,
    );
    Ok(artifact)
}
