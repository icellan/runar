//! Rúnar Compiler (Rust) — library root.
//!
//! Full compilation pipeline:
//!   - IR consumer mode: accepts ANF IR JSON, emits Bitcoin Script.
//!   - Source mode: compiles `.runar.ts` source files through all passes.

pub mod artifact;
pub mod codegen;
pub mod frontend;
pub mod ir;
pub mod refusal;

use artifact::{assemble_artifact, RunarArtifact};
use codegen::emit::emit;
use codegen::optimizer::{optimize_stack_ops, optimize_stack_ops_with_locs};
use codegen::stack::lower_to_stack;
use ir::loader::{load_ir, load_ir_from_str};

use std::path::Path;

// ---------------------------------------------------------------------------
// Pass guards (R-224)
// ---------------------------------------------------------------------------

/// Run one compiler pass with the same panic discipline passes 4 and 5 already
/// had: a panic raised inside it becomes an `Err` carrying the payload, and the
/// default panic hook's "thread 'main' panicked at src/…" banner never reaches
/// the user.
///
/// Before R-224 only passes 4 and 5 were wrapped. Passes 1, 2, 3, 3b, 4.25 and
/// 4.5 ran bare, so an `unreachable!()` / `unwrap()` inside any of them —
/// `frontend::expand_fixed_arrays` alone holds a dozen — would unwind straight
/// out of the compiler: a crash report for a library embedder, and for the CLI
/// a backtrace invitation instead of a diagnostic. The Go / TS / Python / Zig /
/// Ruby / Java tiers all turn a pass-level panic into a diagnostic; this makes
/// the Rust tier do it for EVERY pass rather than for two of them.
///
/// This is a containment boundary, not a licence to panic: no source is known
/// to reach one of those sites today.
fn guarded_pass<T>(prefix: &str, f: impl FnOnce() -> T) -> Result<T, refusal::Refusal> {
    refusal::catch_refusal(prefix, || {
        #[cfg(test)]
        test_panic_point(prefix);
        f()
    })
}

/// Test-only panic injection for `guarded_pass`.
///
/// Every guard in this file is a catch-all for a site no input is known to
/// reach, so the only way to test that the guard is actually THERE is to raise
/// a panic at the boundary on purpose. `#[cfg(test)]`, so release builds carry
/// neither the check nor the thread-local.
#[cfg(test)]
thread_local! {
    static PANIC_IN_PASS: std::cell::RefCell<Option<String>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn test_panic_point(prefix: &str) {
    let armed = PANIC_IN_PASS.with(|c| c.borrow().as_deref() == Some(prefix));
    if armed {
        panic!("injected pass panic");
    }
}

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

/// Validate `constructor_args` shape/keys, bake them into the ANF, then verify
/// no referenced readonly property is left unbaked. Returns a list of error
/// messages (empty = OK). Mirrors the TypeScript `validateConstructorArgsShape`
/// + `findUnbakedReferencedReadonly` pair in
/// `packages/runar-compiler/src/index.ts` (PR #113, fix 1).
///
/// The no-args path returns no errors and mutates nothing — byte-identical to
/// the previous behaviour.
///
/// Check (a) — "positional array" reject — is structurally N/A for the Rust
/// tier: `constructor_args` is a `HashMap<String, serde_json::Value>`, already
/// name-keyed, so no positional array can reach this typed API. Kept as a
/// documented no-op to stay 1:1 with the dynamically-typed tiers.
fn apply_constructor_args(
    program: &mut ir::ANFProgram,
    args: &std::collections::HashMap<String, serde_json::Value>,
) -> Vec<String> {
    if args.is_empty() {
        return Vec::new();
    }

    // (b) Unknown-key reject — every key must name a contract property.
    let prop_name_set: std::collections::HashSet<&str> =
        program.properties.iter().map(|p| p.name.as_str()).collect();
    let mut shape_errors: Vec<String> = Vec::new();
    for key in args.keys() {
        if !prop_name_set.contains(key.as_str()) {
            let prop_names: Vec<&str> =
                program.properties.iter().map(|p| p.name.as_str()).collect();
            shape_errors.push(format!(
                "constructorArgs key '{}' does not match any property of contract '{}' \
                 (properties: [{}]). Nothing would be baked for this key.",
                key,
                program.contract_name,
                prop_names.join(", ")
            ));
        }
    }
    // (d) Value kind / width check (F-101), in property declaration order.
    for prop in &program.properties {
        if let Some(val) = args.get(&prop.name) {
            if let Some(msg) = constructor_arg_type_error(&prop.name, &prop.prop_type, val) {
                shape_errors.push(msg);
            }
        }
    }
    if !shape_errors.is_empty() {
        return shape_errors;
    }

    // Bake.
    for prop in &mut program.properties {
        if let Some(val) = args.get(&prop.name) {
            prop.initial_value = Some(val.clone());
        }
    }

    // (c) Unbaked-referenced-readonly reject.
    find_unbaked_referenced_readonly(program)
}

/// F-101: the diagnostic for a `constructor_args` value that does not match
/// its property's declared type, or `None` when it matches. Stack lowering
/// pushes whatever it is handed — `true` as OP_1, `42` as a 1-byte number, a
/// 6-byte hex string as a 6-byte push — so without this a wrong-typed value
/// where a 20-byte hash belongs compiles cleanly into an unspendable script.
/// Message text is shared verbatim with the TypeScript reference
/// (`constructorArgTypeError` in packages/runar-compiler/src/index.ts).
///
/// "Integer" is what `ir::parse_const_value` reads as one: an integral JSON
/// number or a `"<digits>n"` decimal-bigint string.
fn constructor_arg_type_error(
    name: &str,
    prop_type: &str,
    val: &serde_json::Value,
) -> Option<String> {
    use serde_json::Value;
    use std::str::FromStr;
    let is_int = match val {
        Value::Number(n) => num_bigint::BigInt::from_str(&n.to_string()).is_ok(),
        Value::String(s) => ir::is_decimal_bigint_literal(s),
        _ => false,
    };
    let hex_len = match val {
        Value::String(s)
            if !is_int && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit()) =>
        {
            Some(s.len() / 2)
        }
        _ => None,
    };
    let (expected, ok) = if frontend::typecheck::is_bigint_subtype(prop_type) {
        ("an integer".to_string(), is_int)
    } else if prop_type == "boolean" {
        ("a boolean".to_string(), matches!(val, Value::Bool(_)))
    } else if frontend::typecheck::is_bytestring_subtype(prop_type) {
        match codegen::stack::constructor_slot_value_bytes(prop_type) {
            Some(w) => (
                format!("exactly {} bytes of hex", w),
                hex_len == Some(w as usize),
            ),
            None => ("a hex string".to_string(), hex_len.is_some()),
        }
    } else {
        return Some(format!(
            "constructorArgs value for property '{}' ({}) cannot be baked: \
             unsupported property type.",
            name, prop_type
        ));
    };
    if ok {
        return None;
    }
    let got = match (val, hex_len) {
        (Value::Bool(_), _) => "a boolean".to_string(),
        _ if is_int => "an integer".to_string(),
        (_, Some(n)) => format!("{} bytes of hex", n),
        (Value::String(_), None) => "a non-hex string".to_string(),
        _ => "an unsupported value".to_string(),
    };
    Some(format!(
        "constructorArgs value for property '{}' ({}) must be {}, got {}. \
         Baking it would silently put the wrong value in the locking script.",
        name, prop_type, expected, got
    ))
}

/// After baking `constructor_args`, find readonly properties that are
/// REFERENCED by at least one method body but still have no baked
/// `initial_value`. Such properties would be emitted as OP_0 placeholders,
/// making the compiled script fail opaquely at runtime.
fn find_unbaked_referenced_readonly(program: &ir::ANFProgram) -> Vec<String> {
    let referenced = collect_referenced_props(program);
    let mut errors = Vec::new();
    for prop in &program.properties {
        if prop.readonly && prop.initial_value.is_none() && referenced.contains(&prop.name) {
            errors.push(format!(
                "readonly property '{}' is referenced by a method but has no value after \
                 baking constructorArgs — the emitted script would carry an OP_0 placeholder \
                 that fails at runtime. Provide '{}' in constructorArgs (or give the property \
                 an initializer).",
                prop.name, prop.name
            ));
        }
    }
    errors
}

/// Collect the property names actually referenced by method bodies.
///
/// The raw ANF may load properties that are ultimately dead; only after
/// dead-binding elimination do the surviving `load_prop` nodes reflect real
/// references. DCE is a pure function, so running it here on a probe copy does
/// not perturb the main pipeline. The constructor's `super(...)` call
/// references every property but is never emitted as script code, so it is
/// excluded.
fn collect_referenced_props(program: &ir::ANFProgram) -> std::collections::HashSet<String> {
    let probe = frontend::dce::eliminate_dead_code(program.clone());
    let mut referenced = std::collections::HashSet::new();
    for method in &probe.methods {
        if method.name == "constructor" {
            continue;
        }
        collect_load_prop_refs(&method.body, &mut referenced);
    }
    referenced
}

/// Recursively collect `load_prop` property names from ANF bindings.
fn collect_load_prop_refs(
    bindings: &[ir::ANFBinding],
    out: &mut std::collections::HashSet<String>,
) {
    for binding in bindings {
        match &binding.value {
            ir::ANFValue::LoadProp { name, .. } => {
                out.insert(name.clone());
            }
            ir::ANFValue::If { then, else_branch, .. } => {
                collect_load_prop_refs(then, out);
                collect_load_prop_refs(else_branch, out);
            }
            ir::ANFValue::Loop { body, .. } => {
                collect_load_prop_refs(body, out);
            }
            _ => {}
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
    compile_from_program_with_options(&program, &ir_input_options(opts))
}

/// Compile from an ANF IR JSON string.
pub fn compile_from_ir_str(json_str: &str) -> Result<RunarArtifact, String> {
    compile_from_ir_str_with_options(json_str, &CompileOptions::default())
}

/// Compile from an ANF IR JSON string, with options.
pub fn compile_from_ir_str_with_options(json_str: &str, opts: &CompileOptions) -> Result<RunarArtifact, String> {
    let program = load_ir_from_str(json_str)?;
    compile_from_program_with_options(&program, &ir_input_options(opts))
}

/// Force the ANF constant-folding pass off when compiling already-lowered ANF
/// IR (the `--ir` path). The ANF fold is a source-pipeline optimization;
/// re-running it on pre-lowered IR rewrites `bin_op`s to constants but leaves
/// the now-dead operand bindings in place (fold does no dead-binding
/// elimination), which stack-lowering then emits as wasteful push+drop
/// sequences — diverging from both the fold-OFF goldens and the Zig tier,
/// whose `compileFromIR` never folds IR input (compilers/zig/src/main.zig).
/// Folding stays enabled on the source path (`compile_from_source`).
fn ir_input_options(opts: &CompileOptions) -> CompileOptions {
    CompileOptions { disable_constant_folding: true, ..opts.clone() }
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
    let parse_result = guarded_pass("parse", || frontend::parser::parse_source(source, file_name))
        .map_err(|e| e.message)?;
    if !parse_result.errors.is_empty() {
        let error_msgs: Vec<String> = parse_result.errors.iter().map(|e| e.to_string()).collect();
        return Err(format!("Parse errors:\n  {}", error_msgs.join("\n  ")));
    }

    let contract = parse_result
        .contract
        .ok_or_else(|| "No contract found in source file".to_string())?;

    // Pass 2: Validate
    let validation = guarded_pass("validate", || frontend::validator::validate(&contract))
        .map_err(|e| e.message)?;
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
    let tc_result = guarded_pass("type check", || frontend::typecheck::typecheck(&contract))
        .map_err(|e| e.message)?;
    if !tc_result.errors.is_empty() {
        return Err(format!(
            "Type-check errors:\n  {}",
            tc_result.error_strings().join("\n  ")
        ));
    }

    // Pass 3b: Expand fixed-size array properties into scalar siblings.
    let expand_result = guarded_pass("expand fixed arrays", || {
        frontend::expand_fixed_arrays::expand_fixed_arrays(&contract)
    })
    .map_err(|e| e.message)?;
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

    // Pass 4: ANF Lower (catch panics)
    let mut anf_program = frontend::anf_lower::try_lower_to_anf(&contract)?;

    // Bake constructor args into ANF properties (validated first).
    let arg_errors = apply_constructor_args(&mut anf_program, &opts.constructor_args);
    if !arg_errors.is_empty() {
        return Err(format!(
            "constructorArgs errors:\n  {}",
            arg_errors.join("\n  ")
        ));
    }

    // Pass 4.25: Constant folding (optional)
    if !opts.disable_constant_folding {
        anf_program = guarded_pass("constant folding", || {
            frontend::constant_fold::fold_constants(&anf_program)
        })
        .map_err(|e| e.message)?;
    }

    // Pass 4.5: EC optimization. Delegates internally to frontend::dce
    // for dead-binding cleanup after any EC rewrite.
    let anf_program =
        guarded_pass("ec optimization", || frontend::anf_optimize::optimize_ec(anf_program))
            .map_err(|e| e.message)?;

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
    let parse_result = guarded_pass("parse", || frontend::parser::parse_source(source, file_name))
        .map_err(|e| e.message)?;
    if !parse_result.errors.is_empty() {
        let error_msgs: Vec<String> = parse_result.errors.iter().map(|e| e.to_string()).collect();
        return Err(format!("Parse errors:\n  {}", error_msgs.join("\n  ")));
    }

    let contract = parse_result
        .contract
        .ok_or_else(|| "No contract found in source file".to_string())?;

    let validation = guarded_pass("validate", || frontend::validator::validate(&contract))
        .map_err(|e| e.message)?;
    if !validation.errors.is_empty() {
        return Err(format!(
            "Validation errors:\n  {}",
            validation.error_strings().join("\n  ")
        ));
    }

    let tc_result = guarded_pass("type check", || frontend::typecheck::typecheck(&contract))
        .map_err(|e| e.message)?;
    if !tc_result.errors.is_empty() {
        return Err(format!(
            "Type-check errors:\n  {}",
            tc_result.error_strings().join("\n  ")
        ));
    }

    // Pass 3b: Expand fixed-size array properties into scalar siblings.
    let expand_result = guarded_pass("expand fixed arrays", || {
        frontend::expand_fixed_arrays::expand_fixed_arrays(&contract)
    })
    .map_err(|e| e.message)?;
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

    // Pass 4: ANF Lower (catch panics)
    let mut anf_program = frontend::anf_lower::try_lower_to_anf(&contract)?;

    // Bake constructor args into ANF properties (validated first).
    let arg_errors = apply_constructor_args(&mut anf_program, &opts.constructor_args);
    if !arg_errors.is_empty() {
        return Err(format!(
            "constructorArgs errors:\n  {}",
            arg_errors.join("\n  ")
        ));
    }

    // Pass 4.25: Constant folding (optional)
    if !opts.disable_constant_folding {
        anf_program = guarded_pass("constant folding", || {
            frontend::constant_fold::fold_constants(&anf_program)
        })
        .map_err(|e| e.message)?;
    }

    guarded_pass("ec optimization", || frontend::anf_optimize::optimize_ec(anf_program))
        .map_err(|e| e.message)
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

/// F-107: a readonly property may only be written in the constructor
/// ("cannot assign to readonly property"), and an `update_prop` must name a
/// declared property. Walks every non-constructor method at every nesting
/// depth (`if` arms, `loop` bodies). Port of Go F-004 `checkNoReadonlyWrites`
/// (compilers/go/compiler/ir_frontend_rules.go), diagnostics verbatim.
fn check_ir_no_readonly_writes(program: &ir::ANFProgram) -> Result<(), String> {
    let readonly: std::collections::HashMap<&str, bool> = program
        .properties
        .iter()
        .map(|p| (p.name.as_str(), p.readonly))
        .collect();
    for m in program.methods.iter().filter(|m| m.name != "constructor") {
        check_no_readonly_writes(&m.body, &m.name, &readonly)?;
    }
    Ok(())
}

fn check_no_readonly_writes(
    bindings: &[ir::ANFBinding],
    method_name: &str,
    readonly: &std::collections::HashMap<&str, bool>,
) -> Result<(), String> {
    for b in bindings {
        match &b.value {
            ir::ANFValue::UpdateProp { name, .. } => match readonly.get(name.as_str()) {
                None => {
                    return Err(format!(
                        "IR validation: method '{}' assigns to undeclared property '{}'",
                        method_name, name
                    ))
                }
                Some(true) => {
                    return Err(format!(
                        "IR validation: cannot assign to readonly property '{}' in method '{}'. readonly properties may only be assigned in the constructor; a later load_prop would read the assigned value instead of the one baked into the locking script",
                        name, method_name
                    ))
                }
                Some(false) => {}
            },
            ir::ANFValue::If { then, else_branch, .. } => {
                check_no_readonly_writes(then, method_name, readonly)?;
                check_no_readonly_writes(else_branch, method_name, readonly)?;
            }
            ir::ANFValue::Loop { body, .. } => {
                check_no_readonly_writes(body, method_name, readonly)?;
            }
            _ => {}
        }
    }
    Ok(())
}

/// N-087: the source validator's parentClass rules, which `--ir` never ran. A
/// SmartContract property declared readonly:false got no constructor slot, so
/// `update_prop owner = x; assert(owner == x)` compiled to 76767b8777, which any
/// key spends. Checked in this order, with the diagnostics all seven tiers share
/// (conformance/negatives/ir-parent-class-cases.json): (1) SmartContract /
/// UnsafeSmartContract properties must be readonly; (2) stateful-only nodes
/// require StatefulSmartContract; (3) raw_script (asm) requires
/// UnsafeSmartContract. An absent parentClass (IR older than F-038) is inferred
/// fail-closed: StatefulSmartContract only from a stateful-only node, else
/// UnsafeSmartContract from a raw_script, else SmartContract.
fn check_ir_parent_class_rules(program: &ir::ANFProgram) -> Result<(), String> {
    fn stateful_only_kind(v: &ir::ANFValue) -> Option<&'static str> {
        match v {
            ir::ANFValue::AddOutput { .. } => Some("add_output"),
            ir::ANFValue::AddRawOutput { .. } => Some("add_raw_output"),
            ir::ANFValue::AddDataOutput { .. } => Some("add_data_output"),
            ir::ANFValue::GetStateScript { .. } => Some("get_state_script"),
            ir::ANFValue::DeserializeState { .. } => Some("deserialize_state"),
            _ => None,
        }
    }
    fn walk(bindings: &[ir::ANFBinding], f: &mut dyn FnMut(&ir::ANFValue) -> Result<(), String>) -> Result<(), String> {
        for b in bindings {
            f(&b.value)?;
            match &b.value {
                ir::ANFValue::If { then, else_branch, .. } => {
                    walk(then, f)?;
                    walk(else_branch, f)?;
                }
                ir::ANFValue::Loop { body, .. } => walk(body, f)?,
                _ => {}
            }
        }
        Ok(())
    }
    let (mut has_stateful, mut has_raw) = (false, false);
    for m in &program.methods {
        walk(&m.body, &mut |v| {
            has_stateful |= stateful_only_kind(v).is_some();
            has_raw |= matches!(v, ir::ANFValue::RawScript { .. });
            Ok(())
        })?;
    }
    let pc: &str = if !program.parent_class.is_empty() {
        &program.parent_class
    } else if has_stateful {
        "StatefulSmartContract"
    } else if has_raw {
        "UnsafeSmartContract"
    } else {
        "SmartContract"
    };
    if pc != "StatefulSmartContract" {
        if let Some(p) = program.properties.iter().find(|p| !p.readonly) {
            return Err(format!(
                "IR validation: Property '{}' in {} must be readonly. Use StatefulSmartContract for mutable state.",
                p.name, pc
            ));
        }
    }
    for m in &program.methods {
        walk(&m.body, &mut |v| match stateful_only_kind(v) {
            Some(kind) if pc != "StatefulSmartContract" => Err(format!(
                "IR validation: '{}' in method '{}' is only available in StatefulSmartContract; got {}",
                kind, m.name, pc
            )),
            _ => Ok(()),
        })?;
    }
    for m in &program.methods {
        walk(&m.body, &mut |v| match v {
            ir::ANFValue::RawScript { .. } if pc != "UnsafeSmartContract" => Err(format!(
                "IR validation: 'raw_script' in method '{}' is only available in contracts extending UnsafeSmartContract; got {}",
                m.name, pc
            )),
            _ => Ok(()),
        })?;
    }
    Ok(())
}

/// Compile a parsed ANF program to a Rúnar artifact.
pub fn compile_from_program(program: &ir::ANFProgram) -> Result<RunarArtifact, String> {
    compile_from_program_with_options(program, &CompileOptions::default())
}

/// Compile a parsed ANF program to a Rúnar artifact, with options.
pub fn compile_from_program_with_options(program: &ir::ANFProgram, opts: &CompileOptions) -> Result<RunarArtifact, String> {
    // F-107: the source validator's readonly-write rule, re-asserted on every
    // program that reaches this entry point (the `--ir` path never runs the
    // validator). Same check and wording as Go F-004's checkIRFrontendRules.
    check_ir_parent_class_rules(program)?;
    check_ir_no_readonly_writes(program)?;

    let mut program = program.clone();

    // F-103: bake constructor args (validated first) on the IR / direct-program
    // entry points too, as the TS `compileFromANF` does. The source pipelines
    // bake before calling here and pass empty args, so this is a no-op for them.
    let arg_errors = apply_constructor_args(&mut program, &opts.constructor_args);
    if !arg_errors.is_empty() {
        return Err(format!(
            "constructorArgs errors:\n  {}",
            arg_errors.join("\n  ")
        ));
    }

    // Pass 4.25: Constant folding (optional, in case we receive unoptimized ANF from IR)
    if !opts.disable_constant_folding {
        program = guarded_pass("constant folding", || {
            frontend::constant_fold::fold_constants(&program)
        })
        .map_err(|e| e.message)?;
    }

    // Pass 4.5: EC optimization (in case we receive unoptimized ANF from IR).
    // Delegates internally to frontend::dce for dead-binding cleanup.
    let optimized = guarded_pass("ec optimization", || frontend::anf_optimize::optimize_ec(program))
        .map_err(|e| e.message)?;

    // Pass 5: Stack lowering
    let mut stack_methods = lower_to_stack(&optimized)?;

    // Peephole optimization — runs on Stack IR before emission. Uses the
    // source-loc-preserving variant so the artifact's sourceMap survives
    // the pass: each collapsed peephole window keeps the source location of
    // its head input op.
    for method in &mut stack_methods {
        let (new_ops, new_locs) = optimize_stack_ops_with_locs(&method.ops, &method.source_locs);
        method.ops = new_ops;
        method.source_locs = new_locs;
    }

    // Pass 6: Emit
    let emit_result = guarded_pass("emit", || emit(&stack_methods))
        .map_err(|e| e.message)??;

    let artifact = assemble_artifact(
        &optimized,
        &emit_result.script_hex,
        &emit_result.script_asm,
        emit_result.constructor_slots,
        emit_result.code_sep_index_slots,
        emit_result.code_part_len_slots,
        emit_result.code_separator_index,
        emit_result.code_separator_indices,
        true, // include ANF IR for SDK state auto-computation
        emit_result.source_map,
        emit_result.raw_script_spans,
        &stack_methods,
    )?;
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
    let parse_result =
        match guarded_pass("parse", || frontend::parser::parse_source(source, file_name)) {
            Ok(r) => r,
            Err(e) => {
                result.diagnostics.push(Diagnostic::error(e.message, e.loc));
                return result;
            }
        };
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
    let validation = match guarded_pass("validate", || frontend::validator::validate(contract)) {
        Ok(v) => v,
        Err(e) => {
            result.diagnostics.push(Diagnostic::error(e.message, e.loc));
            return result;
        }
    };
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
    let tc_result = match guarded_pass("type check", || frontend::typecheck::typecheck(contract)) {
        Ok(t) => t,
        Err(e) => {
            result.diagnostics.push(Diagnostic::error(e.message, e.loc));
            return result;
        }
    };
    result.diagnostics.extend(tc_result.errors);

    if result.has_errors() {
        return result;
    }

    if opts.typecheck_only {
        result.success = !result.has_errors();
        return result;
    }

    // Pass 3b: Expand fixed-size array properties into scalar siblings.
    let expand_result = match guarded_pass("expand fixed arrays", || {
        frontend::expand_fixed_arrays::expand_fixed_arrays(contract)
    }) {
        Ok(r) => r,
        Err(e) => {
            result.diagnostics.push(Diagnostic::error(e.message, e.loc));
            return result;
        }
    };
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

    // Pass 4: ANF lowering (catch panics)
    let mut anf_program = match frontend::anf_lower::try_lower_to_anf(contract) {
        Ok(program) => program,
        Err(e) => {
            // R-138: the refusal carries the statement it died on.
            result.diagnostics.push(Diagnostic::error(e.message.clone(), e.loc.clone()));
            return result;
        }
    };

    // Bake constructor args into ANF properties (validated first).
    let arg_errors = apply_constructor_args(&mut anf_program, &opts.constructor_args);
    if !arg_errors.is_empty() {
        for msg in arg_errors {
            result.diagnostics.push(Diagnostic::error(msg, None));
        }
        return result;
    }

    // Pass 4.25: Constant folding (optional)
    if !opts.disable_constant_folding {
        anf_program = match guarded_pass("constant folding", || {
            frontend::constant_fold::fold_constants(&anf_program)
        }) {
            Ok(p) => p,
            Err(e) => {
                result.diagnostics.push(Diagnostic::error(e.message, e.loc));
                return result;
            }
        };
    }

    // Pass 4.5: EC optimization (delegates internally to frontend::dce)
    anf_program =
        match guarded_pass("ec optimization", || frontend::anf_optimize::optimize_ec(anf_program)) {
            Ok(p) => p,
            Err(e) => {
                result.diagnostics.push(Diagnostic::error(e.message, e.loc));
                return result;
            }
        };
    result.anf = Some(anf_program.clone());

    // Issue #109: warn when DCE strips an un-annotated readonly field. Such a
    // field carries no compile-time value (no initializer) and is referenced by
    // no method, so it is eliminated from the locking script entirely —
    // silently dropping deploy-time metadata an author may intend to recover
    // from the on-chain script later. `@embedAlways` fields were forced back in
    // during ANF lowering, so they are "referenced" here and never warn.
    {
        let referenced = collect_referenced_props(&anf_program);
        if let Some(contract_ast) = result.contract.as_ref() {
            for prop in &contract_ast.properties {
                if prop.readonly
                    && !prop.embed_always
                    && prop.initializer.is_none()
                    && !referenced.contains(&prop.name)
                {
                    result.diagnostics.push(Diagnostic::warning(
                        format!(
                            "readonly field '{}' is not referenced in any method body and was \
                             eliminated by DCE; annotate it /** @embedAlways */ to preserve it in \
                             the on-chain script",
                            prop.name
                        ),
                        Some(prop.source_location.clone()),
                    ));
                }
            }
        }
    }

    // Pass 5: Stack lowering (catch panics)
    let stack_result = guarded_pass("stack lowering", || lower_to_stack(&anf_program));

    let mut stack_methods = match stack_result {
        Ok(Ok(methods)) => methods,
        Ok(Err(e)) => {
            // R-138: the refusal carries the ANF binding's source location.
            // The message already begins "stack lowering: " — `catch_refusal`
            // adds the prefix — so do NOT add it again here; that double prefix
            // is what the old `format!` produced.
            let loc = e.loc.clone();
            result.diagnostics.push(Diagnostic::error(e.message.clone(), loc));
            return result;
        }
        Err(e) => {
            result.diagnostics.push(Diagnostic::error(e.message, e.loc));
            return result;
        }
    };

    // Peephole optimization — the SAME source-loc-preserving variant the
    // primary path uses.
    //
    // R-166: this path used to call the plain `optimize_stack_ops` and then
    // blank every location when the op count changed:
    //
    //     if new_ops.len() != method.source_locs.len() {
    //         method.source_locs = vec![None; new_ops.len()];
    //     }
    //
    // The peephole almost always changes the count — a two-line contract goes
    // 8 ops -> 3 — so the fallback fired on essentially every compile and this
    // tier emitted an EMPTY source map for every contract. Measured against the
    // peers on a contract with no crypto in it at all:
    //
    // ```text
    // go 2 mappings   ts 2   python 3   ruby 3   rust 0
    // ```
    //
    // The CLI's `--source` route lands here, not on the primary path, so
    // `--emit-source-map` wrote `{"mappings": []}` for everything. The
    // loc-preserving variant keeps each collapsed window's head location, which
    // is what the primary path already did.
    for method in &mut stack_methods {
        let (new_ops, new_locs) = optimize_stack_ops_with_locs(&method.ops, &method.source_locs);
        method.ops = new_ops;
        method.source_locs = new_locs;
    }

    // Pass 6: Emit (catch panics)
    let emit_result_outer = guarded_pass("emit", || emit(&stack_methods));

    match emit_result_outer {
        Ok(Ok(emit_result)) => {
            let anf_ref = result.anf.as_ref().unwrap();
            let artifact = assemble_artifact(
                anf_ref,
                &emit_result.script_hex,
                &emit_result.script_asm,
                emit_result.constructor_slots,
                emit_result.code_sep_index_slots,
                emit_result.code_part_len_slots,
                emit_result.code_separator_index,
                emit_result.code_separator_indices,
                true,
                emit_result.source_map,
                emit_result.raw_script_spans,
        &stack_methods,
            );
            match artifact {
                Ok(a) => {
                    result.script_hex = Some(emit_result.script_hex);
                    result.script_asm = Some(emit_result.script_asm);
                    result.artifact = Some(a);
                }
                Err(e) => {
                    result.diagnostics.push(Diagnostic::error(e, None));
                }
            }
        }
        Ok(Err(e)) => {
            result.diagnostics.push(Diagnostic::error(
                format!("emit: {}", e),
                None,
            ));
        }
        Err(e) => {
            result.diagnostics.push(Diagnostic::error(e.message, e.loc));
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

// ---------------------------------------------------------------------------
// R-224: every pass is behind a guard
// ---------------------------------------------------------------------------

#[cfg(test)]
mod pass_guard_tests {
    use super::*;

    /// A contract that reaches every pass: it parses, validates, type-checks,
    /// survives fixed-array expansion, folds a constant, runs the EC/DCE
    /// optimiser, lowers to stack and emits.
    const SRC: &str = r#"
import { StatefulSmartContract, assert } from 'runar-lang';

class Guarded extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  public bump(step: bigint) {
    assert(step > 0n);
    this.count = this.count + step + (2n * 3n);
    this.addOutput(1000n, this.count);
  }
}
"#;

    fn arm(pass: &str) {
        PANIC_IN_PASS.with(|c| *c.borrow_mut() = Some(pass.to_string()));
    }

    fn disarm() {
        PANIC_IN_PASS.with(|c| *c.borrow_mut() = None);
    }

    /// Control: with nothing armed the contract compiles. If this ever fails,
    /// the two tests below are vacuous.
    #[test]
    fn control_contract_compiles() {
        disarm();
        let artifact = compile_from_source_str(SRC, Some("Guarded.runar.ts"))
            .expect("control contract must compile");
        assert!(!artifact.script.is_empty(), "control produced an empty script");
    }

    /// A panic raised inside ANY frontend pass on the primary `Result` path
    /// comes back as an `Err`, prefixed with the pass that raised it — never as
    /// an unwind out of the compiler.
    #[test]
    fn primary_path_guards_every_pass() {
        for pass in [
            "parse",
            "validate",
            "type check",
            "expand fixed arrays",
            "constant folding",
            "ec optimization",
            "emit",
        ] {
            arm(pass);
            let outcome = compile_from_source_str(SRC, Some("Guarded.runar.ts"));
            disarm();
            let err = outcome.expect_err(&format!("pass '{}' swallowed the injected panic", pass));
            assert!(
                err.starts_with(pass),
                "pass '{}' reported through the wrong guard: {}",
                pass,
                err
            );
            assert!(
                err.contains("injected pass panic"),
                "pass '{}' lost the panic payload: {}",
                pass,
                err
            );
        }
    }

    /// Same, for the diagnostic-collecting entry point the CLI's `--source`
    /// route uses. Pass 5 and pass 6 are reachable here too.
    #[test]
    fn diagnostic_path_guards_every_pass() {
        for pass in [
            "parse",
            "validate",
            "type check",
            "expand fixed arrays",
            "constant folding",
            "ec optimization",
            "stack lowering",
            "emit",
        ] {
            arm(pass);
            let result = compile_from_source_str_with_result(
                SRC,
                Some("Guarded.runar.ts"),
                &CompileOptions::default(),
            );
            disarm();
            assert!(
                !result.success,
                "pass '{}' swallowed the injected panic and reported success",
                pass
            );
            let joined = result
                .diagnostics
                .iter()
                .map(|d| d.to_string())
                .collect::<Vec<_>>()
                .join("\n");
            assert!(
                joined.contains("injected pass panic"),
                "pass '{}' lost the panic payload: {}",
                pass,
                joined
            );
            assert!(
                joined.contains(pass),
                "pass '{}' reported through the wrong guard: {}",
                pass,
                joined
            );
        }
    }
}
