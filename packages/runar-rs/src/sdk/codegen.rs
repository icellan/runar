//! Native Rust code generation for the Runar SDK.
//!
//! Generates typed Rust wrapper structs from compiled Runar artifacts,
//! using an embedded Mustache template and a minimal template renderer.

use super::types::*;
use std::collections::HashMap;

// ---------------------------------------------------------------------------
// Type mapping
// ---------------------------------------------------------------------------

/// Map an ABI type string to a Rust type string.
fn map_type_to_rust(abi_type: &str) -> &'static str {
    match abi_type {
        "bigint" => "BigInt",
        "boolean" => "bool",
        "Sig" | "PubKey" | "ByteString" | "Addr" | "Ripemd160" | "Sha256" | "Point"
        | "SigHashPreimage" => "String",
        _ => "SdkValue",
    }
}

/// Build the Rust expression to convert a typed param into SdkValue.
fn rust_sdk_value_expr(abi_type: &str, var_name: &str) -> String {
    match abi_type {
        "Sig" | "PubKey" => "SdkValue::Auto".to_string(),
        "bigint" => format!("SdkValue::BigInt({})", var_name),
        "boolean" => format!("SdkValue::Bool({})", var_name),
        _ => format!("SdkValue::Bytes({})", var_name),
    }
}

// ---------------------------------------------------------------------------
// Name conversion utilities
// ---------------------------------------------------------------------------

/// Convert camelCase to snake_case: "releaseBySeller" -> "release_by_seller"
fn to_snake_case(name: &str) -> String {
    let mut result = String::with_capacity(name.len() + 4);
    for (i, ch) in name.chars().enumerate() {
        if ch.is_uppercase() {
            if i > 0 {
                // Check for acronym boundaries: e.g. "PKH" -> "p_k_h" is wrong,
                // but we follow the same regex logic as the TS implementation:
                //   /([A-Z]+)([A-Z][a-z])/g -> $1_$2
                //   /([a-z0-9])([A-Z])/g   -> $1_$2
                let prev = name.chars().nth(i - 1).unwrap_or('a');
                if prev.is_lowercase() || prev.is_ascii_digit() {
                    result.push('_');
                } else if prev.is_uppercase() {
                    // Peek at the next char: if it's lowercase, insert underscore
                    // before current char (acronym boundary).
                    if let Some(next) = name.chars().nth(i + 1) {
                        if next.is_lowercase() {
                            result.push('_');
                        }
                    }
                }
            }
            result.push(ch.to_lowercase().next().unwrap());
        } else {
            result.push(ch);
        }
    }
    result
}

/// Convert camelCase to PascalCase (capitalize first letter).
fn to_pascal_case(name: &str) -> String {
    let mut chars = name.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => {
            let mut s = c.to_uppercase().to_string();
            s.extend(chars);
            s
        }
    }
}

/// Reserved method names on the generated wrapper struct.
const RESERVED_NAMES: &[&str] = &["connect", "deploy", "contract", "get_locking_script"];

/// Generate a safe method name (snake_case), avoiding collisions with wrapper methods.
fn safe_rust_method_name(name: &str) -> String {
    let snake = to_snake_case(name);
    if RESERVED_NAMES.contains(&snake.as_str()) {
        format!("call_{}", snake)
    } else {
        snake
    }
}

// ---------------------------------------------------------------------------
// ABI analysis utilities
// ---------------------------------------------------------------------------

/// Whether the artifact represents a stateful contract.
fn is_stateful_artifact(artifact: &RunarArtifact) -> bool {
    match &artifact.state_fields {
        Some(fields) => !fields.is_empty(),
        None => false,
    }
}

/// Get public methods from an artifact.
fn get_public_methods(artifact: &RunarArtifact) -> Vec<&AbiMethod> {
    artifact.abi.methods.iter().filter(|m| m.is_public).collect()
}

/// Determine if a method is terminal (no state continuation output).
fn is_terminal_method(method: &AbiMethod, is_stateful: bool) -> bool {
    if !is_stateful {
        return true; // stateless contracts are always terminal
    }
    // Use the explicit is_terminal flag if present
    if let Some(terminal) = method.is_terminal {
        return terminal;
    }
    // Fallback for older artifacts without is_terminal:
    // check for the absence of _changePKH in params
    !method.params.iter().any(|p| p.name == "_changePKH")
}

/// Whether a param is hidden (auto-computed by SDK).
fn is_hidden_param(p: &AbiParam, is_stateful: bool) -> bool {
    if p.param_type == "Sig" {
        return true;
    }
    if is_stateful {
        if p.param_type == "SigHashPreimage" {
            return true;
        }
        if p.name == "_changePKH" || p.name == "_changeAmount" || p.name == "_newAmount" {
            return true;
        }
    }
    false
}

/// Whether a param should be excluded from the SDK args array entirely.
fn is_excluded_from_sdk_args(p: &AbiParam, is_stateful: bool) -> bool {
    if !is_stateful {
        return false;
    }
    p.param_type == "SigHashPreimage"
        || p.name == "_changePKH"
        || p.name == "_changeAmount"
        || p.name == "_newAmount"
}

// ---------------------------------------------------------------------------
// Context types for the Mustache template
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct CtxParam {
    name: String,
    param_type: String,
    abi_type: String,
    is_last: bool,
}

#[derive(Debug, Clone)]
struct CtxSigParam {
    name: String,
    arg_index: usize,
    is_last: bool,
}

#[derive(Debug, Clone)]
struct CtxMethod {
    original_name: String,
    name: String,
    capitalized_name: String,
    is_terminal: bool,
    is_stateful_method: bool,
    has_sig_params: bool,
    has_user_params: bool,
    user_params: Vec<CtxParam>,
    sdk_args_expr: String,
    sig_params: Vec<CtxSigParam>,
    sig_entries_expr: String,
    has_prepare_user_params: bool,
    prepare_user_params: Vec<CtxParam>,
}

#[derive(Debug, Clone)]
struct CodegenContext {
    contract_name: String,
    is_stateful: bool,
    has_stateful_methods: bool,
    has_terminal_methods: bool,
    has_constructor_params: bool,
    has_big_int_params: bool,
    constructor_params: Vec<CtxParam>,
    constructor_args_expr: String,
    methods: Vec<CtxMethod>,
}

// ---------------------------------------------------------------------------
// Context builder
// ---------------------------------------------------------------------------

fn build_codegen_context(artifact: &RunarArtifact) -> CodegenContext {
    let is_stateful = is_stateful_artifact(artifact);
    let public_methods = get_public_methods(artifact);

    // Constructor params
    let ctor_params = &artifact.abi.constructor.params;
    let ctor_len = ctor_params.len();
    let constructor_params: Vec<CtxParam> = ctor_params
        .iter()
        .enumerate()
        .map(|(i, p)| CtxParam {
            name: to_snake_case(&p.name),
            param_type: map_type_to_rust(&p.param_type).to_string(),
            abi_type: p.param_type.clone(),
            is_last: i == ctor_len - 1,
        })
        .collect();

    let mut has_big_int_params = ctor_params.iter().any(|p| p.param_type == "bigint");

    // Constructor args expression (using SdkValue wrappers)
    let constructor_args_expr = constructor_params
        .iter()
        .map(|p| rust_sdk_value_expr(&p.abi_type, &p.name))
        .collect::<Vec<_>>()
        .join(", ");

    // Methods
    let has_stateful_methods =
        is_stateful && public_methods.iter().any(|m| !is_terminal_method(m, is_stateful));
    let has_terminal_methods = public_methods
        .iter()
        .any(|m| is_terminal_method(m, is_stateful));

    let methods: Vec<CtxMethod> = public_methods
        .iter()
        .map(|method| {
            let terminal = is_terminal_method(method, is_stateful);
            let method_name = safe_rust_method_name(&method.name);

            // User-visible params (not hidden)
            let user_params_raw: Vec<&AbiParam> = method
                .params
                .iter()
                .filter(|p| !is_hidden_param(p, is_stateful))
                .collect();
            let user_len = user_params_raw.len();
            let user_params: Vec<CtxParam> = user_params_raw
                .iter()
                .enumerate()
                .map(|(i, p)| CtxParam {
                    name: to_snake_case(&p.name),
                    param_type: map_type_to_rust(&p.param_type).to_string(),
                    abi_type: p.param_type.clone(),
                    is_last: i == user_len - 1,
                })
                .collect();

            if user_params_raw.iter().any(|p| p.param_type == "bigint") {
                has_big_int_params = true;
            }

            // SDK args (all params except SigHashPreimage/_changePKH/_changeAmount/_newAmount for stateful)
            let sdk_args_raw: Vec<&AbiParam> = method
                .params
                .iter()
                .filter(|p| !is_excluded_from_sdk_args(p, is_stateful))
                .collect();

            let sdk_args_expr = sdk_args_raw
                .iter()
                .map(|p| {
                    if is_hidden_param(p, is_stateful) {
                        "SdkValue::Auto".to_string()
                    } else {
                        let param_name = to_snake_case(&p.name);
                        rust_sdk_value_expr(&p.param_type, &param_name)
                    }
                })
                .collect::<Vec<_>>()
                .join(", ");

            // Sig params (for prepare/finalize)
            let sig_params_raw: Vec<(usize, &AbiParam)> = sdk_args_raw
                .iter()
                .enumerate()
                .filter(|(_, p)| p.param_type == "Sig")
                .map(|(i, p)| (i, *p))
                .collect();
            let sig_len = sig_params_raw.len();
            let sig_params: Vec<CtxSigParam> = sig_params_raw
                .iter()
                .enumerate()
                .map(|(j, (arg_idx, p))| CtxSigParam {
                    name: to_snake_case(&p.name),
                    arg_index: *arg_idx,
                    is_last: j == sig_len - 1,
                })
                .collect();

            let sig_entries_expr = sig_params
                .iter()
                .map(|sp| format!("({}, {})", sp.arg_index, sp.name))
                .collect::<Vec<_>>()
                .join(", ");

            // Prepare user params (user params minus Sig)
            let prepare_user_params_raw: Vec<&CtxParam> = user_params
                .iter()
                .filter(|p| p.abi_type != "Sig")
                .collect();
            let prep_len = prepare_user_params_raw.len();
            let prepare_user_params: Vec<CtxParam> = prepare_user_params_raw
                .iter()
                .enumerate()
                .map(|(i, p)| CtxParam {
                    name: p.name.clone(),
                    param_type: p.param_type.clone(),
                    abi_type: p.abi_type.clone(),
                    is_last: i == prep_len - 1,
                })
                .collect();

            let capitalized_name = to_pascal_case(&method.name);

            CtxMethod {
                original_name: method.name.clone(),
                name: method_name,
                capitalized_name,
                is_terminal: terminal,
                is_stateful_method: !terminal && is_stateful,
                has_sig_params: !sig_params.is_empty(),
                has_user_params: !user_params.is_empty(),
                user_params,
                sdk_args_expr,
                sig_params,
                sig_entries_expr,
                has_prepare_user_params: !prepare_user_params.is_empty(),
                prepare_user_params,
            }
        })
        .collect();

    CodegenContext {
        contract_name: artifact.contract_name.clone(),
        is_stateful,
        has_stateful_methods,
        has_terminal_methods,
        has_constructor_params: !constructor_params.is_empty(),
        has_big_int_params,
        constructor_params,
        constructor_args_expr,
        methods,
    }
}

// ---------------------------------------------------------------------------
// Minimal Mustache renderer
// ---------------------------------------------------------------------------
//
// Supports:
//   {{var}}                     — variable interpolation
//   {{#section}}...{{/section}} — truthy section (bool true, or iterate array)
//   {{^section}}...{{/section}} — inverted section (bool false / empty array)
//
// This is intentionally minimal — just enough for the wrapper.rs.mustache template.

/// A value in the Mustache context.
#[derive(Debug, Clone)]
enum MustacheValue {
    Str(String),
    Bool(bool),
    List(Vec<HashMap<String, MustacheValue>>),
}

/// Render a Mustache template with the given context.
fn mustache_render(template: &str, ctx: &HashMap<String, MustacheValue>) -> String {
    render_section(template, ctx)
}

fn render_section(template: &str, ctx: &HashMap<String, MustacheValue>) -> String {
    let mut result = String::with_capacity(template.len());
    let mut pos = 0;

    while pos < template.len() {
        // Find the next {{
        if let Some(tag_start) = find_tag_open(template, pos) {
            // Append everything before the tag
            result.push_str(&template[pos..tag_start]);

            // Find the closing }}
            let tag_content_start = tag_start + 2;
            if let Some(tag_end) = template[tag_content_start..].find("}}") {
                let tag_end_abs = tag_content_start + tag_end;
                let tag_content = template[tag_content_start..tag_end_abs].trim();
                let after_tag = tag_end_abs + 2;

                if let Some(section_name) = tag_content.strip_prefix('#') {
                    // Section start: {{#name}}
                    let section_name = section_name.trim();
                    let (body, end_pos) =
                        find_section_body(template, after_tag, section_name);
                    render_truthy_section(&mut result, section_name, body, ctx);
                    pos = end_pos;
                } else if let Some(section_name) = tag_content.strip_prefix('^') {
                    // Inverted section: {{^name}}
                    let section_name = section_name.trim();
                    let (body, end_pos) =
                        find_section_body(template, after_tag, section_name);
                    render_inverted_section(&mut result, section_name, body, ctx);
                    pos = end_pos;
                } else {
                    // Variable interpolation: {{name}}
                    if let Some(val) = ctx.get(tag_content) {
                        match val {
                            MustacheValue::Str(s) => result.push_str(s),
                            MustacheValue::Bool(b) => {
                                result.push_str(if *b { "true" } else { "false" })
                            }
                            MustacheValue::List(_) => {} // lists don't interpolate
                        }
                    }
                    pos = after_tag;
                }
            } else {
                // No closing }}, just append the rest
                result.push_str(&template[pos..]);
                break;
            }
        } else {
            // No more tags, append the rest
            result.push_str(&template[pos..]);
            break;
        }
    }

    result
}

/// Find the start position of the next `{{` at or after `from`.
fn find_tag_open(template: &str, from: usize) -> Option<usize> {
    template[from..].find("{{").map(|i| from + i)
}

/// Find the matching `{{/name}}` for a section, handling nesting.
/// Returns (body_content, position_after_closing_tag).
fn find_section_body<'a>(
    template: &'a str,
    start: usize,
    name: &str,
) -> (&'a str, usize) {
    let open_tag = format!("{{{{#{}}}}}", name);
    let close_tag = format!("{{{{/{}}}}}", name);
    let mut depth = 1;
    let mut search_pos = start;

    while depth > 0 {
        // Find the next open or close tag for this name
        let next_open = template[search_pos..].find(&open_tag).map(|i| search_pos + i);
        let next_close = template[search_pos..]
            .find(&close_tag)
            .map(|i| search_pos + i);

        match (next_open, next_close) {
            (Some(o), Some(c)) if o < c => {
                depth += 1;
                search_pos = o + open_tag.len();
            }
            (_, Some(c)) => {
                depth -= 1;
                if depth == 0 {
                    let body = &template[start..c];
                    let end_pos = c + close_tag.len();
                    return (body, end_pos);
                }
                search_pos = c + close_tag.len();
            }
            _ => {
                // No more closing tags found — return rest as body
                return (&template[start..], template.len());
            }
        }
    }

    (&template[start..], template.len())
}

/// Render a truthy section: if bool true, render body once; if list, iterate.
fn render_truthy_section(
    result: &mut String,
    name: &str,
    body: &str,
    ctx: &HashMap<String, MustacheValue>,
) {
    match ctx.get(name) {
        Some(MustacheValue::Bool(true)) => {
            result.push_str(&render_section(body, ctx));
        }
        Some(MustacheValue::List(items)) if !items.is_empty() => {
            for item in items {
                // Merge parent context with item context (item takes precedence)
                let mut merged = ctx.clone();
                for (k, v) in item {
                    merged.insert(k.clone(), v.clone());
                }
                result.push_str(&render_section(body, &merged));
            }
        }
        _ => {} // false, missing, or empty list — skip
    }
}

/// Render an inverted section: if bool false / missing / empty list, render body.
fn render_inverted_section(
    result: &mut String,
    name: &str,
    body: &str,
    ctx: &HashMap<String, MustacheValue>,
) {
    match ctx.get(name) {
        Some(MustacheValue::Bool(true)) => {} // skip
        Some(MustacheValue::List(items)) if !items.is_empty() => {} // skip
        _ => {
            result.push_str(&render_section(body, ctx));
        }
    }
}

// ---------------------------------------------------------------------------
// Context conversion: CodegenContext -> Mustache HashMap
// ---------------------------------------------------------------------------

fn param_to_map(p: &CtxParam) -> HashMap<String, MustacheValue> {
    let mut m = HashMap::new();
    m.insert("name".to_string(), MustacheValue::Str(p.name.clone()));
    m.insert("type".to_string(), MustacheValue::Str(p.param_type.clone()));
    m.insert("abiType".to_string(), MustacheValue::Str(p.abi_type.clone()));
    m.insert("isLast".to_string(), MustacheValue::Bool(p.is_last));
    m
}

fn sig_param_to_map(sp: &CtxSigParam) -> HashMap<String, MustacheValue> {
    let mut m = HashMap::new();
    m.insert("name".to_string(), MustacheValue::Str(sp.name.clone()));
    m.insert(
        "argIndex".to_string(),
        MustacheValue::Str(sp.arg_index.to_string()),
    );
    m.insert("isLast".to_string(), MustacheValue::Bool(sp.is_last));
    m
}

fn method_to_map(
    method: &CtxMethod,
    parent_ctx: &HashMap<String, MustacheValue>,
) -> HashMap<String, MustacheValue> {
    let mut m = HashMap::new();
    m.insert(
        "originalName".to_string(),
        MustacheValue::Str(method.original_name.clone()),
    );
    m.insert("name".to_string(), MustacheValue::Str(method.name.clone()));
    m.insert(
        "capitalizedName".to_string(),
        MustacheValue::Str(method.capitalized_name.clone()),
    );
    m.insert(
        "isTerminal".to_string(),
        MustacheValue::Bool(method.is_terminal),
    );
    m.insert(
        "isStatefulMethod".to_string(),
        MustacheValue::Bool(method.is_stateful_method),
    );
    m.insert(
        "hasSigParams".to_string(),
        MustacheValue::Bool(method.has_sig_params),
    );
    m.insert(
        "hasUserParams".to_string(),
        MustacheValue::Bool(method.has_user_params),
    );
    m.insert(
        "userParams".to_string(),
        MustacheValue::List(method.user_params.iter().map(param_to_map).collect()),
    );
    m.insert(
        "sdkArgsExpr".to_string(),
        MustacheValue::Str(method.sdk_args_expr.clone()),
    );
    m.insert(
        "sigParams".to_string(),
        MustacheValue::List(method.sig_params.iter().map(sig_param_to_map).collect()),
    );
    m.insert(
        "sigEntriesExpr".to_string(),
        MustacheValue::Str(method.sig_entries_expr.clone()),
    );
    m.insert(
        "hasPrepareUserParams".to_string(),
        MustacheValue::Bool(method.has_prepare_user_params),
    );
    m.insert(
        "prepareUserParams".to_string(),
        MustacheValue::List(
            method
                .prepare_user_params
                .iter()
                .map(param_to_map)
                .collect(),
        ),
    );

    // Inherit contractName from parent context
    if let Some(cn) = parent_ctx.get("contractName") {
        m.insert("contractName".to_string(), cn.clone());
    }

    m
}

fn context_to_mustache(ctx: &CodegenContext) -> HashMap<String, MustacheValue> {
    let mut m = HashMap::new();
    m.insert(
        "contractName".to_string(),
        MustacheValue::Str(ctx.contract_name.clone()),
    );
    m.insert(
        "isStateful".to_string(),
        MustacheValue::Bool(ctx.is_stateful),
    );
    m.insert(
        "hasStatefulMethods".to_string(),
        MustacheValue::Bool(ctx.has_stateful_methods),
    );
    m.insert(
        "hasTerminalMethods".to_string(),
        MustacheValue::Bool(ctx.has_terminal_methods),
    );
    m.insert(
        "hasConstructorParams".to_string(),
        MustacheValue::Bool(ctx.has_constructor_params),
    );
    m.insert(
        "hasBigIntParams".to_string(),
        MustacheValue::Bool(ctx.has_big_int_params),
    );
    m.insert(
        "constructorParams".to_string(),
        MustacheValue::List(ctx.constructor_params.iter().map(param_to_map).collect()),
    );
    m.insert(
        "constructorArgsExpr".to_string(),
        MustacheValue::Str(ctx.constructor_args_expr.clone()),
    );

    // Methods are rendered as a list section
    let method_maps: Vec<HashMap<String, MustacheValue>> = ctx
        .methods
        .iter()
        .map(|method| method_to_map(method, &m))
        .collect();
    m.insert("methods".to_string(), MustacheValue::List(method_maps));

    m
}

// ---------------------------------------------------------------------------
// Template (embedded from codegen/templates/wrapper.rs.mustache)
// ---------------------------------------------------------------------------

const RUST_TEMPLATE: &str = r#"// Generated by: runar codegen
// Source: {{contractName}}
// Do not edit manually.

use std::collections::HashMap;
use num_bigint::BigInt;
use runar::sdk::{
    RunarContract, RunarArtifact, SdkValue, Provider, Signer,
    TransactionData, DeployOptions, CallOptions, PreparedCall,
};
use runar::sdk::deployment::build_p2pkh_script_from_address;

{{#hasTerminalMethods}}
/// Terminal output specification — accepts address or raw script hex.
pub struct TerminalOutput {
    pub satoshis: i64,
    pub address: Option<String>,
    pub script_hex: Option<String>,
}

fn resolve_terminal_outputs(outputs: &[TerminalOutput]) -> Vec<runar::sdk::TerminalOutput> {
    outputs.iter().map(|o| {
        let script_hex = match (&o.script_hex, &o.address) {
            (Some(s), _) => s.clone(),
            (None, Some(a)) => build_p2pkh_script_from_address(a),
            _ => panic!("TerminalOutput must have either address or script_hex"),
        };
        runar::sdk::TerminalOutput { script_hex, satoshis: o.satoshis }
    }).collect()
}

{{/hasTerminalMethods}}
{{#hasStatefulMethods}}
/// Options for stateful method calls on {{contractName}}.
pub struct {{contractName}}StatefulCallOptions {
    pub satoshis: Option<i64>,
    pub change_address: Option<String>,
    pub change_pub_key: Option<String>,
    pub new_state: Option<HashMap<String, SdkValue>>,
}

impl {{contractName}}StatefulCallOptions {
    fn to_call_options(&self) -> CallOptions {
        CallOptions {
            satoshis: self.satoshis,
            change_address: self.change_address.clone(),
            change_pub_key: self.change_pub_key.clone(),
            new_state: self.new_state.clone(),
            ..Default::default()
        }
    }
}

{{/hasStatefulMethods}}
/// Constructor arguments for {{contractName}}.
{{#hasConstructorParams}}
pub struct {{contractName}}ConstructorArgs {
{{#constructorParams}}
    pub {{name}}: {{type}},
{{/constructorParams}}
}
{{/hasConstructorParams}}

/// Typed wrapper for the {{contractName}} contract.
pub struct {{contractName}}Contract {
    inner: RunarContract,
}

impl {{contractName}}Contract {
{{#hasConstructorParams}}
    /// Create a new {{contractName}}Contract with typed constructor arguments.
    pub fn new(artifact: RunarArtifact, args: {{contractName}}ConstructorArgs) -> Self {
        let ctor_args = vec![{{constructorArgsExpr}}];
        Self { inner: RunarContract::new(artifact, ctor_args) }
    }
{{/hasConstructorParams}}
{{^hasConstructorParams}}
    /// Create a new {{contractName}}Contract.
    pub fn new(artifact: RunarArtifact) -> Self {
        Self { inner: RunarContract::new(artifact, vec![]) }
    }
{{/hasConstructorParams}}

    /// Reconnect to an existing contract UTXO by transaction ID.
    pub fn from_txid(
        artifact: RunarArtifact,
        txid: &str,
        output_index: usize,
        provider: &dyn Provider,
    ) -> Result<Self, String> {
        let inner = RunarContract::from_txid(artifact, txid, output_index, provider)?;
        Ok(Self { inner })
    }

    /// Store a provider and signer for implicit use.
    pub fn connect(&mut self, provider: Box<dyn Provider>, signer: Box<dyn Signer>) {
        self.inner.connect(provider, signer);
    }

    /// Deploy the contract on-chain.
    pub fn deploy(
        &mut self,
        provider: &mut dyn Provider,
        signer: &dyn Signer,
        options: &DeployOptions,
    ) -> Result<(String, TransactionData), String> {
        self.inner.deploy(provider, signer, options)
    }

    /// Returns the full locking script hex.
    pub fn get_locking_script(&self) -> String {
        self.inner.get_locking_script()
    }

    /// Returns a reference to the underlying RunarContract.
    pub fn contract(&self) -> &RunarContract {
        &self.inner
    }

    /// Returns a mutable reference to the underlying RunarContract.
    pub fn contract_mut(&mut self) -> &mut RunarContract {
        &mut self.inner
    }

{{#methods}}
    /// Call the {{originalName}} method.
    pub fn {{name}}(
        &mut self,
{{#userParams}}
        {{name}}: {{type}},
{{/userParams}}
        provider: &mut dyn Provider,
        signer: &dyn Signer,
{{#isStatefulMethod}}
        options: Option<&{{contractName}}StatefulCallOptions>,
{{/isStatefulMethod}}
{{#isTerminal}}
        outputs: Option<&[TerminalOutput]>,
{{/isTerminal}}
    ) -> Result<(String, TransactionData), String> {
        let args = vec![{{sdkArgsExpr}}];
{{#isTerminal}}
        let opts = outputs.map(|o| {
            let mut co = CallOptions::default();
            co.terminal_outputs = Some(resolve_terminal_outputs(o));
            co
        });
        self.inner.call("{{originalName}}", &args, provider, signer, opts.as_ref())
{{/isTerminal}}
{{#isStatefulMethod}}
        let opts = options.map(|o| o.to_call_options());
        self.inner.call("{{originalName}}", &args, provider, signer, opts.as_ref())
{{/isStatefulMethod}}
    }

{{#hasSigParams}}
    /// Prepare the {{originalName}} call without signing (for external signers).
    pub fn prepare_{{name}}(
        &mut self,
{{#prepareUserParams}}
        {{name}}: {{type}},
{{/prepareUserParams}}
        provider: &mut dyn Provider,
        signer: &dyn Signer,
{{#isStatefulMethod}}
        options: Option<&{{contractName}}StatefulCallOptions>,
{{/isStatefulMethod}}
{{#isTerminal}}
        outputs: Option<&[TerminalOutput]>,
{{/isTerminal}}
    ) -> Result<PreparedCall, String> {
        let args = vec![{{sdkArgsExpr}}];
{{#isTerminal}}
        let opts = outputs.map(|o| {
            let mut co = CallOptions::default();
            co.terminal_outputs = Some(resolve_terminal_outputs(o));
            co
        });
        self.inner.prepare_call("{{originalName}}", &args, provider, signer, opts.as_ref())
{{/isTerminal}}
{{#isStatefulMethod}}
        let opts = options.map(|o| o.to_call_options());
        self.inner.prepare_call("{{originalName}}", &args, provider, signer, opts.as_ref())
{{/isStatefulMethod}}
    }

    /// Finalize a prepared {{originalName}} call with external signatures.
    pub fn finalize_{{name}}(
        &mut self,
        prepared: &PreparedCall,
{{#sigParams}}
        {{name}}: String,
{{/sigParams}}
        provider: &mut dyn Provider,
    ) -> Result<(String, TransactionData), String> {
        let sigs: HashMap<usize, String> = HashMap::from([{{#sigParams}}({{argIndex}}, {{name}}){{^isLast}}, {{/isLast}}{{/sigParams}}]);
        self.inner.finalize_call(prepared, &sigs, provider)
    }

{{/hasSigParams}}
{{/methods}}
}
"#;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a typed Rust wrapper from a compiled Runar artifact.
///
/// The output is a complete Rust source file containing a wrapper struct
/// with typed methods for each public contract method, constructor args
/// struct, and helper types for terminal/stateful calls.
pub fn generate_rust(artifact: &RunarArtifact) -> String {
    let ctx = build_codegen_context(artifact);
    let mustache_ctx = context_to_mustache(&ctx);
    mustache_render(RUST_TEMPLATE, &mustache_ctx)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_artifact(
        name: &str,
        ctor_params: Vec<AbiParam>,
        methods: Vec<AbiMethod>,
        state_fields: Option<Vec<StateField>>,
    ) -> RunarArtifact {
        RunarArtifact {
            version: "0.1.0".to_string(),
            contract_name: name.to_string(),
            abi: Abi {
                constructor: AbiConstructor {
                    params: ctor_params,
                },
                methods,
            },
            script: "5151".to_string(),
            state_fields,
            constructor_slots: None,
            code_separator_index: None,
            code_separator_indices: None,
            anf: None,
        }
    }

    // -----------------------------------------------------------------------
    // Name conversion
    // -----------------------------------------------------------------------

    #[test]
    fn test_to_snake_case() {
        assert_eq!(to_snake_case("releaseBySeller"), "release_by_seller");
        assert_eq!(to_snake_case("increment"), "increment");
        assert_eq!(to_snake_case("pubKeyHash"), "pub_key_hash");
        assert_eq!(to_snake_case("_changePKH"), "_change_pkh");
    }

    #[test]
    fn test_to_pascal_case() {
        assert_eq!(to_pascal_case("increment"), "Increment");
        assert_eq!(to_pascal_case("releaseBySeller"), "ReleaseBySeller");
    }

    #[test]
    fn test_safe_rust_method_name() {
        assert_eq!(safe_rust_method_name("unlock"), "unlock");
        assert_eq!(safe_rust_method_name("connect"), "call_connect");
        assert_eq!(safe_rust_method_name("deploy"), "call_deploy");
        assert_eq!(
            safe_rust_method_name("getLockingScript"),
            "call_get_locking_script"
        );
    }

    // -----------------------------------------------------------------------
    // Type mapping
    // -----------------------------------------------------------------------

    #[test]
    fn test_map_type_to_rust() {
        assert_eq!(map_type_to_rust("bigint"), "BigInt");
        assert_eq!(map_type_to_rust("boolean"), "bool");
        assert_eq!(map_type_to_rust("Sig"), "String");
        assert_eq!(map_type_to_rust("ByteString"), "String");
        assert_eq!(map_type_to_rust("unknown"), "SdkValue");
    }

    #[test]
    fn test_rust_sdk_value_expr() {
        assert_eq!(rust_sdk_value_expr("bigint", "count"), "SdkValue::BigInt(count)");
        assert_eq!(rust_sdk_value_expr("boolean", "flag"), "SdkValue::Bool(flag)");
        assert_eq!(rust_sdk_value_expr("Sig", "sig"), "SdkValue::Auto");
        assert_eq!(
            rust_sdk_value_expr("ByteString", "data"),
            "SdkValue::Bytes(data)"
        );
    }

    // -----------------------------------------------------------------------
    // Mustache renderer
    // -----------------------------------------------------------------------

    #[test]
    fn test_mustache_variable() {
        let mut ctx = HashMap::new();
        ctx.insert("name".to_string(), MustacheValue::Str("Counter".to_string()));
        assert_eq!(mustache_render("Hello {{name}}!", &ctx), "Hello Counter!");
    }

    #[test]
    fn test_mustache_truthy_section() {
        let mut ctx = HashMap::new();
        ctx.insert("show".to_string(), MustacheValue::Bool(true));
        assert_eq!(
            mustache_render("{{#show}}visible{{/show}}", &ctx),
            "visible"
        );
    }

    #[test]
    fn test_mustache_falsy_section() {
        let mut ctx = HashMap::new();
        ctx.insert("show".to_string(), MustacheValue::Bool(false));
        assert_eq!(mustache_render("{{#show}}hidden{{/show}}", &ctx), "");
    }

    #[test]
    fn test_mustache_inverted_section() {
        let mut ctx = HashMap::new();
        ctx.insert("hasItems".to_string(), MustacheValue::Bool(false));
        assert_eq!(
            mustache_render("{{^hasItems}}empty{{/hasItems}}", &ctx),
            "empty"
        );
    }

    #[test]
    fn test_mustache_list_section() {
        let mut ctx = HashMap::new();
        let items = vec![
            {
                let mut m = HashMap::new();
                m.insert("val".to_string(), MustacheValue::Str("a".to_string()));
                m
            },
            {
                let mut m = HashMap::new();
                m.insert("val".to_string(), MustacheValue::Str("b".to_string()));
                m
            },
        ];
        ctx.insert("items".to_string(), MustacheValue::List(items));
        assert_eq!(
            mustache_render("{{#items}}[{{val}}]{{/items}}", &ctx),
            "[a][b]"
        );
    }

    // -----------------------------------------------------------------------
    // Full codegen: stateless contract
    // -----------------------------------------------------------------------

    #[test]
    fn test_generate_stateless_no_params() {
        let artifact = make_artifact(
            "Simple",
            vec![],
            vec![AbiMethod {
                name: "unlock".to_string(),
                params: vec![],
                is_public: true,
                is_terminal: None,
            }],
            None,
        );
        let output = generate_rust(&artifact);
        assert!(output.contains("pub struct SimpleContract"));
        assert!(output.contains("pub fn new(artifact: RunarArtifact) -> Self"));
        assert!(output.contains("pub fn unlock("));
        assert!(!output.contains("ConstructorArgs"));
    }

    #[test]
    fn test_generate_with_constructor_params() {
        let artifact = make_artifact(
            "P2PKH",
            vec![AbiParam {
                name: "pubKeyHash".to_string(),
                param_type: "ByteString".to_string(),
            }],
            vec![AbiMethod {
                name: "unlock".to_string(),
                params: vec![
                    AbiParam {
                        name: "sig".to_string(),
                        param_type: "Sig".to_string(),
                    },
                    AbiParam {
                        name: "pubKey".to_string(),
                        param_type: "PubKey".to_string(),
                    },
                ],
                is_public: true,
                is_terminal: None,
            }],
            None,
        );
        let output = generate_rust(&artifact);
        assert!(output.contains("pub struct P2PKHConstructorArgs"));
        assert!(output.contains("pub pub_key_hash: String"));
        assert!(output.contains("SdkValue::Bytes(pub_key_hash)"));
        assert!(output.contains("pub fn unlock("));
        // Sig params should generate prepare/finalize
        assert!(output.contains("pub fn prepare_unlock("));
        assert!(output.contains("pub fn finalize_unlock("));
    }

    // -----------------------------------------------------------------------
    // Full codegen: stateful contract
    // -----------------------------------------------------------------------

    #[test]
    fn test_generate_stateful_contract() {
        let artifact = make_artifact(
            "Counter",
            vec![AbiParam {
                name: "count".to_string(),
                param_type: "bigint".to_string(),
            }],
            vec![AbiMethod {
                name: "increment".to_string(),
                params: vec![
                    AbiParam {
                        name: "txPreimage".to_string(),
                        param_type: "SigHashPreimage".to_string(),
                    },
                    AbiParam {
                        name: "_changePKH".to_string(),
                        param_type: "ByteString".to_string(),
                    },
                    AbiParam {
                        name: "_changeAmount".to_string(),
                        param_type: "bigint".to_string(),
                    },
                ],
                is_public: true,
                is_terminal: None,
            }],
            Some(vec![StateField {
                name: "count".to_string(),
                field_type: "bigint".to_string(),
                index: 0,
                initial_value: None,
            }]),
        );
        let output = generate_rust(&artifact);
        assert!(output.contains("pub struct CounterStatefulCallOptions"));
        assert!(output.contains("pub fn increment("));
        assert!(output.contains("options: Option<&CounterStatefulCallOptions>"));
        // Hidden params should not appear as user params
        assert!(!output.contains("tx_preimage: String"));
        assert!(!output.contains("_change_pkh"));
    }

    // -----------------------------------------------------------------------
    // Reserved method names
    // -----------------------------------------------------------------------

    #[test]
    fn test_reserved_method_names() {
        let artifact = make_artifact(
            "MyContract",
            vec![],
            vec![AbiMethod {
                name: "connect".to_string(),
                params: vec![],
                is_public: true,
                is_terminal: None,
            }],
            None,
        );
        let output = generate_rust(&artifact);
        assert!(output.contains("pub fn call_connect("));
        assert!(output.contains("Call the connect method"));
    }
}
