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
    /// Stop compilation after the parse pass (pass 1).
    pub parse_only: bool,
    /// Stop compilation after the validate pass (pass 2).
    pub validate_only: bool,
    /// Stop compilation after the type-check pass (pass 3).
    pub typecheck_only: bool,
    /// Bake property values into the locking script (replaces OP_0 placeholders).
    /// Keys are property names; values are JSON values (string, number, bool).
    pub constructor_args: std::collections::HashMap<String, serde_json::Value>,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            disable_constant_folding: false,
            parse_only: false,
            validate_only: false,
            typecheck_only: false,
            constructor_args: std::collections::HashMap::new(),
        }
    }
}

/// Apply constructor args by setting ANF property initial_value fields.
fn apply_constructor_args(program: &mut ir::ANFProgram, args: &std::collections::HashMap<String, serde_json::Value>) {
    if args.is_empty() {
        return;
    }
    for prop in &mut program.properties {
        if let Some(val) = args.get(&prop.name) {
            prop.initial_value = Some(val.clone());
        }
    }
}

// ---------------------------------------------------------------------------
// CompileResult — rich compilation output (mirrors TypeScript CompileResult)
// ---------------------------------------------------------------------------

/// Rich compilation result that collects ALL diagnostics from ALL passes
/// and returns partial results as they become available.
///
/// Unlike the `Result<RunarArtifact, String>` API, `CompileResult` never
/// returns an error — all errors are captured in the `diagnostics` vector.
pub struct CompileResult {
    /// The parsed AST (available after pass 1 — parse).
    pub contract: Option<frontend::ast::ContractNode>,
    /// The A-Normal Form IR (available after pass 4 — ANF lowering).
    pub anf: Option<ir::ANFProgram>,
    /// ALL diagnostics from ALL passes (errors + warnings).
    pub diagnostics: Vec<frontend::diagnostic::Diagnostic>,
    /// True only if there are no error-severity diagnostics.
    pub success: bool,
    /// The final compiled artifact (available if compilation succeeds).
    pub artifact: Option<RunarArtifact>,
    /// The hex-encoded Bitcoin Script (available if compilation succeeds).
    pub script_hex: Option<String>,
    /// The human-readable ASM (available if compilation succeeds).
    pub script_asm: Option<String>,
}

impl CompileResult {
    fn new() -> Self {
        Self {
            contract: None,
            anf: None,
            diagnostics: Vec::new(),
            success: false,
            artifact: None,
            script_hex: None,
            script_asm: None,
        }
    }

    fn has_errors(&self) -> bool {
        self.diagnostics.iter().any(|d| d.severity == frontend::diagnostic::Severity::Error)
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
            validation.error_strings().join("\n  ")
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
            tc_result.error_strings().join("\n  ")
        ));
    }

    // Pass 3b: Expand fixed-size array properties into scalar siblings.
    let expand_result = frontend::expand_fixed_arrays::expand_fixed_arrays(&contract);
    if !expand_result.errors.is_empty() {
        let error_msgs: Vec<String> = expand_result
            .errors
            .iter()
            .map(|e| e.format_message())
            .collect();
        return Err(format!(
            "Expand-fixed-arrays errors:\n  {}",
            error_msgs.join("\n  ")
        ));
    }
    let contract = expand_result.contract;

    // Pass 4: ANF Lower
    let mut anf_program = frontend::anf_lower::lower_to_anf(&contract);

    // Bake constructor args into ANF properties.
    apply_constructor_args(&mut anf_program, &opts.constructor_args);

    // Pass 4.25: Constant folding (optional)
    if !opts.disable_constant_folding {
        anf_program = frontend::constant_fold::fold_constants(&anf_program);
    }

    // Pass 4.5: EC optimization
    let anf_program = frontend::anf_optimize::optimize_ec(anf_program);

    // Passes 5-6: Backend (stack lowering + emit)
    // Constant folding already ran above; skip it in compile_from_program.
    let backend_opts = CompileOptions { disable_constant_folding: true, ..Default::default() };
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
            validation.error_strings().join("\n  ")
        ));
    }

    let tc_result = frontend::typecheck::typecheck(&contract);
    if !tc_result.errors.is_empty() {
        return Err(format!(
            "Type-check errors:\n  {}",
            tc_result.error_strings().join("\n  ")
        ));
    }

    // Pass 3b: Expand fixed-size array properties into scalar siblings.
    let expand_result = frontend::expand_fixed_arrays::expand_fixed_arrays(&contract);
    if !expand_result.errors.is_empty() {
        let error_msgs: Vec<String> = expand_result
            .errors
            .iter()
            .map(|e| e.format_message())
            .collect();
        return Err(format!(
            "Expand-fixed-arrays errors:\n  {}",
            error_msgs.join("\n  ")
        ));
    }
    let contract = expand_result.contract;

    let mut anf_program = frontend::anf_lower::lower_to_anf(&contract);

    // Bake constructor args into ANF properties.
    apply_constructor_args(&mut anf_program, &opts.constructor_args);

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
        return (parse_result.error_strings(), vec![]);
    }
    let contract = match parse_result.contract {
        Some(c) => c,
        None => return (vec!["No contract found".to_string()], vec![]),
    };
    let result = frontend::validator::validate(&contract);
    (result.error_strings(), result.warning_strings())
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
    // Note: source_locs must be resized to match the new ops length since the
    // peephole optimizer may combine adjacent ops (reducing the count).
    for method in &mut stack_methods {
        let new_ops = optimize_stack_ops(&method.ops);
        // After optimization the ops array may have a different length, so rebuild
        // source_locs with the same length (None for new/merged ops).
        method.source_locs = vec![None; new_ops.len()];
        method.ops = new_ops;
    }

    // Pass 6: Emit
    let emit_result = emit(&stack_methods)?;

    let artifact = assemble_artifact(
        &optimized,
        &emit_result.script_hex,
        &emit_result.script_asm,
        emit_result.constructor_slots,
        emit_result.code_sep_index_slots,
        emit_result.code_separator_index,
        emit_result.code_separator_indices,
        true, // include ANF IR for SDK state auto-computation
        emit_result.source_map,
    );
    Ok(artifact)
}

// ---------------------------------------------------------------------------
// CompileResult API — collect all diagnostics, return partial results
// ---------------------------------------------------------------------------

/// Compile from a source string, collecting ALL diagnostics from ALL passes
/// and returning partial results as they become available.
///
/// Unlike `compile_from_source_str_with_options`, this function never returns
/// an error — all errors are captured in `CompileResult.diagnostics`.
pub fn compile_from_source_str_with_result(
    source: &str,
    file_name: Option<&str>,
    opts: &CompileOptions,
) -> CompileResult {
    use frontend::diagnostic::Diagnostic;

    let mut result = CompileResult::new();

    // Pass 1: Parse (auto-selects parser based on file extension)
    let parse_result = frontend::parser::parse_source(source, file_name);
    result.diagnostics.extend(parse_result.errors);
    result.contract = parse_result.contract;

    if result.has_errors() || result.contract.is_none() {
        if result.contract.is_none() && !result.has_errors() {
            result.diagnostics.push(Diagnostic::error(
                "No contract found in source file",
                None,
            ));
        }
        return result;
    }

    if opts.parse_only {
        result.success = !result.has_errors();
        return result;
    }

    // Pass 2: Validate
    let contract = result.contract.as_ref().unwrap();
    let validation = frontend::validator::validate(contract);
    result.diagnostics.extend(validation.errors);
    result.diagnostics.extend(validation.warnings);

    if result.has_errors() {
        return result;
    }

    if opts.validate_only {
        result.success = !result.has_errors();
        return result;
    }

    // Pass 3: Type-check
    let tc_result = frontend::typecheck::typecheck(contract);
    result.diagnostics.extend(tc_result.errors);

    if result.has_errors() {
        return result;
    }

    if opts.typecheck_only {
        result.success = !result.has_errors();
        return result;
    }

    // Pass 3b: Expand fixed-size array properties into scalar siblings.
    let expand_result = frontend::expand_fixed_arrays::expand_fixed_arrays(contract);
    if !expand_result.errors.is_empty() {
        result.diagnostics.extend(expand_result.errors);
    }
    if result.has_errors() {
        return result;
    }
    let expanded_contract = expand_result.contract;
    // Switch the working contract over to the expanded form. Downstream
    // passes operate on this owned clone; the previously-borrowed `contract`
    // reference from `result.contract.as_ref()` is no longer used below.
    let contract = &expanded_contract;
    // Keep result.contract as the pre-expansion AST (mirrors TS spike).

    // Pass 4: ANF lowering
    let mut anf_program = frontend::anf_lower::lower_to_anf(contract);

    // Bake constructor args into ANF properties.
    apply_constructor_args(&mut anf_program, &opts.constructor_args);

    // Pass 4.25: Constant folding (optional)
    if !opts.disable_constant_folding {
        anf_program = frontend::constant_fold::fold_constants(&anf_program);
    }

    // Pass 4.5: EC optimization
    anf_program = frontend::anf_optimize::optimize_ec(anf_program);
    result.anf = Some(anf_program.clone());

    // Pass 5: Stack lowering (catch panics)
    let stack_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        lower_to_stack(&anf_program)
    }));

    let mut stack_methods = match stack_result {
        Ok(Ok(methods)) => methods,
        Ok(Err(e)) => {
            result.diagnostics.push(Diagnostic::error(
                format!("stack lowering: {}", e),
                None,
            ));
            return result;
        }
        Err(panic_val) => {
            let msg = if let Some(s) = panic_val.downcast_ref::<&str>() {
                format!("stack lowering panic: {}", s)
            } else if let Some(s) = panic_val.downcast_ref::<String>() {
                format!("stack lowering panic: {}", s)
            } else {
                "stack lowering panic: unknown error".to_string()
            };
            result.diagnostics.push(Diagnostic::error(msg, None));
            return result;
        }
    };

    // Peephole optimization
    for method in &mut stack_methods {
        let new_ops = optimize_stack_ops(&method.ops);
        method.source_locs = vec![None; new_ops.len()];
        method.ops = new_ops;
    }

    // Pass 6: Emit (catch panics)
    let emit_result_outer = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        emit(&stack_methods)
    }));

    match emit_result_outer {
        Ok(Ok(emit_result)) => {
            let anf_ref = result.anf.as_ref().unwrap();
            let artifact = assemble_artifact(
                anf_ref,
                &emit_result.script_hex,
                &emit_result.script_asm,
                emit_result.constructor_slots,
                emit_result.code_sep_index_slots,
                emit_result.code_separator_index,
                emit_result.code_separator_indices,
                true,
                emit_result.source_map,
            );
            result.script_hex = Some(emit_result.script_hex);
            result.script_asm = Some(emit_result.script_asm);
            result.artifact = Some(artifact);
        }
        Ok(Err(e)) => {
            result.diagnostics.push(Diagnostic::error(
                format!("emit: {}", e),
                None,
            ));
        }
        Err(panic_val) => {
            let msg = if let Some(s) = panic_val.downcast_ref::<&str>() {
                format!("emit panic: {}", s)
            } else if let Some(s) = panic_val.downcast_ref::<String>() {
                format!("emit panic: {}", s)
            } else {
                "emit panic: unknown error".to_string()
            };
            result.diagnostics.push(Diagnostic::error(msg, None));
        }
    }

    result.success = !result.has_errors();
    result
}

/// Compile from a source file on disk, collecting ALL diagnostics.
pub fn compile_from_source_with_result(
    path: &Path,
    opts: &CompileOptions,
) -> CompileResult {
    use frontend::diagnostic::Diagnostic;

    let source = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) => {
            let mut result = CompileResult::new();
            result.diagnostics.push(Diagnostic::error(
                format!("reading source file: {}", e),
                None,
            ));
            return result;
        }
    };
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "contract.ts".to_string());
    compile_from_source_str_with_result(&source, Some(&file_name), opts)
}
