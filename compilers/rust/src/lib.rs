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

/// Options controlling the compilation pipeline.
#[derive(Debug, Clone)]
pub struct CompileOptions {
    /// When true, skip the constant-folding optimisation pass.
    pub disable_constant_folding: bool,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            disable_constant_folding: false,
        }
    }
}

/// Compile from an ANF IR JSON file on disk.
pub fn compile_from_ir(path: &Path) -> Result<RunarArtifact, String> {
    compile_from_ir_with_options(path, &CompileOptions::default())
}

/// Compile from an ANF IR JSON file on disk, with options.
pub fn compile_from_ir_with_options(path: &Path, opts: &CompileOptions) -> Result<RunarArtifact, String> {
    let program = load_ir(path)?;
    compile_from_program_with_options(&program, opts)
}

/// Compile from an ANF IR JSON string.
pub fn compile_from_ir_str(json_str: &str) -> Result<RunarArtifact, String> {
    compile_from_ir_str_with_options(json_str, &CompileOptions::default())
}

/// Compile from an ANF IR JSON string, with options.
pub fn compile_from_ir_str_with_options(json_str: &str, opts: &CompileOptions) -> Result<RunarArtifact, String> {
    let program = load_ir_from_str(json_str)?;
    compile_from_program_with_options(&program, opts)
}

/// Compile from a `.runar.ts` source file on disk.
pub fn compile_from_source(path: &Path) -> Result<RunarArtifact, String> {
    compile_from_source_with_options(path, &CompileOptions::default())
}

/// Compile from a `.runar.ts` source file on disk, with options.
pub fn compile_from_source_with_options(path: &Path, opts: &CompileOptions) -> Result<RunarArtifact, String> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| format!("reading source file: {}", e))?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "contract.ts".to_string());
    compile_from_source_str_with_options(&source, Some(&file_name), opts)
}

/// Compile from a `.runar.ts` source string.
pub fn compile_from_source_str(
    source: &str,
    file_name: Option<&str>,
) -> Result<RunarArtifact, String> {
    compile_from_source_str_with_options(source, file_name, &CompileOptions::default())
}

/// Compile from a `.runar.ts` source string, with options.
pub fn compile_from_source_str_with_options(
    source: &str,
    file_name: Option<&str>,
    opts: &CompileOptions,
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
    let mut anf_program = frontend::anf_lower::lower_to_anf(&contract);

    // Pass 4.25: Constant folding (optional)
    if !opts.disable_constant_folding {
        anf_program = frontend::constant_fold::fold_constants(&anf_program);
    }

    // Pass 4.5: EC optimization
    let anf_program = frontend::anf_optimize::optimize_ec(anf_program);

    // Passes 5-6: Backend (stack lowering + emit)
    // Constant folding already ran above; skip it in compile_from_program.
    let backend_opts = CompileOptions { disable_constant_folding: true };
    compile_from_program_with_options(&anf_program, &backend_opts)
}

/// Compile from a `.runar.ts` source file to ANF IR only (passes 1-4).
pub fn compile_source_to_ir(path: &Path) -> Result<ir::ANFProgram, String> {
    compile_source_to_ir_with_options(path, &CompileOptions::default())
}

/// Compile from a `.runar.ts` source file to ANF IR only (passes 1-4), with options.
pub fn compile_source_to_ir_with_options(path: &Path, opts: &CompileOptions) -> Result<ir::ANFProgram, String> {
    let source = std::fs::read_to_string(path)
        .map_err(|e| format!("reading source file: {}", e))?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "contract.ts".to_string());
    compile_source_str_to_ir_with_options(&source, Some(&file_name), opts)
}

/// Compile from a `.runar.ts` source string to ANF IR only (passes 1-4).
pub fn compile_source_str_to_ir(
    source: &str,
    file_name: Option<&str>,
) -> Result<ir::ANFProgram, String> {
    compile_source_str_to_ir_with_options(source, file_name, &CompileOptions::default())
}

/// Compile from a `.runar.ts` source string to ANF IR only (passes 1-4), with options.
pub fn compile_source_str_to_ir_with_options(
    source: &str,
    file_name: Option<&str>,
    opts: &CompileOptions,
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

    let mut anf_program = frontend::anf_lower::lower_to_anf(&contract);

    // Pass 4.25: Constant folding (optional)
    if !opts.disable_constant_folding {
        anf_program = frontend::constant_fold::fold_constants(&anf_program);
    }

    Ok(frontend::anf_optimize::optimize_ec(anf_program))
}

/// Run only the parse + validate passes on a source string.
/// Returns `(errors, warnings)`. Exposed for testing warnings.
pub fn frontend_validate(source: &str, file_name: Option<&str>) -> (Vec<String>, Vec<String>) {
    let parse_result = frontend::parser::parse_source(source, file_name);
    if !parse_result.errors.is_empty() {
        return (parse_result.errors, vec![]);
    }
    let contract = match parse_result.contract {
        Some(c) => c,
        None => return (vec!["No contract found".to_string()], vec![]),
    };
    let result = frontend::validator::validate(&contract);
    (result.errors, result.warnings)
}

/// Compile a parsed ANF program to a Rúnar artifact.
pub fn compile_from_program(program: &ir::ANFProgram) -> Result<RunarArtifact, String> {
    compile_from_program_with_options(program, &CompileOptions::default())
}

/// Compile a parsed ANF program to a Rúnar artifact, with options.
pub fn compile_from_program_with_options(program: &ir::ANFProgram, opts: &CompileOptions) -> Result<RunarArtifact, String> {
    // Pass 4.25: Constant folding (optional, in case we receive unoptimized ANF from IR)
    let mut program = program.clone();
    if !opts.disable_constant_folding {
        program = frontend::constant_fold::fold_constants(&program);
    }

    // Pass 4.5: EC optimization (in case we receive unoptimized ANF from IR)
    let optimized = frontend::anf_optimize::optimize_ec(program);

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
        emit_result.code_separator_index,
        emit_result.code_separator_indices,
        true, // include ANF IR for SDK state auto-computation
    );
    Ok(artifact)
}
