//! ANF IR loader — reads and validates ANF IR from JSON.

use std::fs;
use std::path::Path;

use super::{ANFBinding, ANFProgram, ANFValue};
use super::input_limits::{
    assert_ir_bytes_under_limit, assert_ir_nesting_under_limit, assert_no_json_floats,
};

/// Load an ANF IR program from a JSON file on disk.
///
/// Rejects oversized (>MAX_IR_BYTES) or deeply-nested (>MAX_IR_NESTING)
/// payloads with a typed-error-derived error string BEFORE `serde_json`
/// runs. BUG-008 follow-up.
pub fn load_ir(path: &Path) -> Result<ANFProgram, String> {
    let data = fs::read_to_string(path)
        .map_err(|e| format!("reading IR file: {}", e))?;
    load_ir_from_str(&data)
}

/// Load an ANF IR program from a JSON string.
///
/// Rejects oversized (>MAX_IR_BYTES) or deeply-nested (>MAX_IR_NESTING)
/// payloads BEFORE `serde_json::from_str` runs. BUG-008 follow-up.
pub fn load_ir_from_str(json_str: &str) -> Result<ANFProgram, String> {
    // DoS-bound guards run before serde_json::from_str so a malicious
    // payload cannot exhaust memory (size) or the thread stack (nesting)
    // inside the deserializer.
    if let Some(e) = assert_ir_bytes_under_limit(json_str.as_bytes()) {
        return Err(e.to_string());
    }
    if let Some(e) = assert_ir_nesting_under_limit(json_str.as_bytes()) {
        return Err(e.to_string());
    }
    // N-131: refuse float syntax BEFORE serde runs. Past this line the
    // f64 -> integer narrowing has already happened and the original token
    // is gone; `1e50` in a `load_const` saturated to i128::MAX here.
    if let Some(e) = assert_no_json_floats(json_str.as_bytes()) {
        return Err(e.to_string());
    }
    let program: ANFProgram = serde_json::from_str(json_str)
        .map_err(|e| describe_ir_parse_error(&e))?;
    validate_ir(&program)?;
    Ok(program)
}

/// Load an ANF IR program from a JSON string, returning typed errors on
/// DoS-bound rejection. Wraps `load_ir_from_str`; callers wanting
/// `errors.As`-style typed inspection use this entry point. BUG-008
/// follow-up.
pub fn load_ir_from_str_typed(
    json_str: &str,
) -> Result<ANFProgram, IRLoaderError> {
    if let Some(e) = assert_ir_bytes_under_limit(json_str.as_bytes()) {
        return Err(IRLoaderError::Size(e));
    }
    if let Some(e) = assert_ir_nesting_under_limit(json_str.as_bytes()) {
        return Err(IRLoaderError::Nesting(e));
    }
    // N-131 — see load_ir_from_str. Both entry points are the trust boundary;
    // guarding one would leave the other open.
    if let Some(e) = assert_no_json_floats(json_str.as_bytes()) {
        return Err(IRLoaderError::Float(e));
    }
    serde_json::from_str::<ANFProgram>(json_str)
        .map_err(|e| IRLoaderError::Other(describe_ir_parse_error(&e)))
        .and_then(|p| {
            validate_ir(&p).map_err(IRLoaderError::Other)?;
            Ok(p)
        })
}

/// Typed-error variant returned by `load_ir_from_str_typed`. BUG-008
/// follow-up.
#[derive(Debug)]
pub enum IRLoaderError {
    Size(super::input_limits::IRSizeExceededError),
    Nesting(super::input_limits::IRNestingExceededError),
    /// A number written in float syntax. N-131.
    Float(super::input_limits::IRFloatValueError),
    Other(String),
}

impl std::fmt::Display for IRLoaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IRLoaderError::Size(e) => write!(f, "{}", e),
            IRLoaderError::Nesting(e) => write!(f, "{}", e),
            IRLoaderError::Float(e) => write!(f, "{}", e),
            IRLoaderError::Other(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for IRLoaderError {}


/// Turn serde's "unknown variant" into the shape the peer tiers use (R-177).
///
/// `ANFValue` is `#[serde(tag = "kind")]` with no catch-all, so an unrecognised
/// kind is rejected inside `serde_json::from_str` — before any of this module's
/// own validation runs. That is correct and it is not going to change: serde's
/// message is the most informative of the seven tiers, because it also lists
/// the kinds that ARE known.
///
/// What it lacked is the words every other tier says. Go answers
/// `IR validation: method unlock binding t1 has unknown kind "not_a_real_kind"`
/// and Java `unknown ANF kind 'not_a_real_kind' ...`; this tier answered
/// `invalid IR JSON: unknown variant ...`, so a caller grepping the diagnostic
/// for "unknown ANF kind" found it in six tiers and not the seventh.
fn describe_ir_parse_error(e: &serde_json::Error) -> String {
    let text = e.to_string();
    if let Some(rest) = text.strip_prefix("unknown variant `") {
        if let Some(end) = rest.find('`') {
            return format!(
                "IR validation: unknown ANF kind {:?} — {}",
                &rest[..end],
                text
            );
        }
    }
    format!("invalid IR JSON: {}", text)
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/// Maximum number of iterations a single loop binding may unroll to.
///
/// The bound already existed on the `--ir` input path in the Go tier
/// (`ir.MaxLoopCount`) but nothing applied it to a loop written in source, in
/// any tier. A source contract could therefore ask for an unroll count no
/// machine can honour, and each tier failed differently — here `to_i64()`
/// returned `None` and `unwrap_or(0)` silently DROPPED the loop body.
/// CL-BUG-088.
pub const MAX_LOOP_COUNT: u32 = 10_000;


/// Every `ANFValue` variant's JSON `kind`.
///
/// R-177: nothing CALLS this any more — the `KNOWN_KINDS` list it fed was a
/// second, hand-maintained copy of the variant names, and the check that
/// compared them could not fire (see validate_bindings). It is kept, and
/// deliberately not deleted with the rest, because an exhaustive match over the
/// closed enum is this tier's build-time guard against a new ANF kind slipping
/// through unwired: adding a variant fails to compile here. That role is
/// documented in tests/unknown_anf_kind_tests.rs, which names this function as
/// one of the dispatchers that must list every variant.
#[allow(dead_code)]
fn kind_name(value: &ANFValue) -> &'static str {
    match value {
        ANFValue::LoadParam { .. } => "load_param",
        ANFValue::LoadProp { .. } => "load_prop",
        ANFValue::LoadConst { .. } => "load_const",
        ANFValue::BinOp { .. } => "bin_op",
        ANFValue::UnaryOp { .. } => "unary_op",
        ANFValue::Call { .. } => "call",
        ANFValue::MethodCall { .. } => "method_call",
        ANFValue::If { .. } => "if",
        ANFValue::Loop { .. } => "loop",
        ANFValue::Assert { .. } => "assert",
        ANFValue::UpdateProp { .. } => "update_prop",
        ANFValue::GetStateScript { .. } => "get_state_script",
        ANFValue::CheckPreimage { .. } => "check_preimage",
        ANFValue::DeserializeState { .. } => "deserialize_state",
        ANFValue::AddOutput { .. } => "add_output",
        ANFValue::AddRawOutput { .. } => "add_raw_output",
        ANFValue::AddDataOutput { .. } => "add_data_output",
        ANFValue::ArrayLiteral { .. } => "array_literal",
        ANFValue::RawScript { .. } => "raw_script",
    }
}

/// Reports whether `s` contains only hex digits (0-9, a-f, A-F).
/// An empty string is considered valid hex.
fn is_hex_string(s: &str) -> bool {
    s.chars().all(|c| c.is_ascii_hexdigit())
}

fn validate_ir(program: &ANFProgram) -> Result<(), String> {
    if program.contract_name.is_empty() {
        return Err("IR validation: contractName is required".into());
    }

    for (i, prop) in program.properties.iter().enumerate() {
        if prop.name.is_empty() {
            return Err(format!("IR validation: property[{}] has empty name", i));
        }
        if prop.prop_type.is_empty() {
            return Err(format!(
                "IR validation: property {} has empty type",
                prop.name
            ));
        }
    }

    // R-126 / CL-BUG-164: an add_output must name exactly one state value per
    // MUTABLE property. Counted once, up front.
    let mutable_count = program.properties.iter().filter(|p| !p.readonly).count();

    for (i, method) in program.methods.iter().enumerate() {
        if method.name.is_empty() {
            return Err(format!("IR validation: method[{}] has empty name", i));
        }
        for (j, param) in method.params.iter().enumerate() {
            if param.name.is_empty() {
                return Err(format!(
                    "IR validation: method {} param[{}] has empty name",
                    method.name, j
                ));
            }
            if param.param_type.is_empty() {
                return Err(format!(
                    "IR validation: method {} param {} has empty type",
                    method.name, param.name
                ));
            }
        }
        validate_bindings(&method.body, &method.name, mutable_count)?;
    }

    // N-113 / R-081: a contract with no public method has no spending entry
    // point and emits an EMPTY locking script — which is anyone-can-spend, not
    // merely useless. On the real @bsv/sdk `Spend` engine under full consensus
    // rules, an empty locking script with the one-byte push-only witness OP_1
    // (0x51) validates. Before this guard the --ir path exited 0 and handed the
    // SDKs a well-formed artifact whose "script" was "".
    //
    // The source pipeline already rejects the same shape in
    // frontend/validator.rs; validate_ir is reached only from the IR loader, so
    // this closes the rule's gap on externally supplied IR.
    //
    // Checked LAST so the structural diagnostics above keep priority — a
    // malformed binding is the more actionable error when both are present.
    // Mirrors compilers/go/ir/loader.go, including the ordering.
    //
    // N-113: the CONSTRUCTOR does not count. This check mirrors
    // frontend/validator.rs, but runs over a differently-shaped list: the AST
    // keeps the constructor in its own field while ANF lowering flattens it
    // INTO `program.methods`, so one `isPublic: true` on the constructor
    // walked past the guard. It is never a spending entry point (emit and
    // stack lowering both filter it out by NAME) and the contract emitted an
    // EMPTY locking script at exit 0.
    if !program
        .methods
        .iter()
        .any(|m| m.is_public && m.name != "constructor")
    {
        return Err(format!(
            "IR validation: contract {} has no public methods — no spending entry points; an empty locking script is anyone-can-spend",
            program.contract_name
        ));
    }

    Ok(())
}

fn validate_bindings(
    bindings: &[ANFBinding],
    method_name: &str,
    mutable_count: usize,
) -> Result<(), String> {
    for (i, binding) in bindings.iter().enumerate() {
        if binding.name.is_empty() {
            return Err(format!(
                "IR validation: method {} binding[{}] has empty name",
                method_name, i
            ));
        }

        // R-177: a `!KNOWN_KINDS.contains(kind_name(&binding.value))` check
        // used to sit here. It could not fire for two independent reasons:
        // `kind_name` maps an ALREADY-DESERIALISED ANFValue to its name, so it
        // only ever returns a known kind, and serde rejects an unrecognised
        // `kind` before this function is called at all. The rejection now
        // happens where it really happens — see describe_ir_parse_error.

        // R-128 / R-165: builtin call arity. The source pipeline type-checks
        // every call; `--ir` runs no frontend, so a wrong-arity call used to
        // reach stack lowering, where each dispatch family pops args.len()
        // from the stack MODEL and then emits a FIXED-arity opcode blob. `cat`
        // with one argument compiled to a bare OP_CAT; `assert` with none
        // compiled to an EMPTY script, dropping the contract's only guard.
        if let ANFValue::Call { func, args, .. } = &binding.value {
            let got = args.len();
            if func == "merkleRootPoseidon2KB" {
                // 8 leaf elements + 8 per proof level + index + depth.
                if got < 10 {
                    return Err(format!(
                        "IR validation: method {} binding {} calls {}() with {} argument(s); \
                         it takes at least 10 arguments (8 leaf + index + depth)",
                        method_name, binding.name, func, got
                    ));
                }
                if (got - 10) % 8 != 0 {
                    return Err(format!(
                        "IR validation: method {} binding {} calls {}() with {} argument(s); \
                         it takes 8*depth + 10 arguments",
                        method_name, binding.name, func, got
                    ));
                }
            } else if let Some(allowed) = crate::frontend::typecheck::builtin_allowed_arity(func) {
                if !allowed.contains(&got) {
                    // "exactly" is load-bearing: R-067's delegate-arity tests
                    // assert the diagnostic says the arity is exact, and this
                    // check now fires before the lowering-level one they were
                    // written against.
                    let wanted = if allowed.len() == 1 {
                        format!("exactly {}", allowed[0])
                    } else {
                        let head: Vec<String> =
                            allowed[..allowed.len() - 1].iter().map(|a| a.to_string()).collect();
                        format!("{} or {}", head.join(", "), allowed[allowed.len() - 1])
                    };
                    return Err(format!(
                        "IR validation: method {} binding {} calls {}() with {} argument(s); it takes {}",
                        method_name, binding.name, func, got, wanted
                    ));
                }
            }
        }

        // R-164 / CL-BUG-134: `super` outside a constructor.
        //
        // `super` emits no opcodes — the constructor args are already on the
        // stack — but stack lowering pushes a stackMap slot for it anyway:
        // +1 model, +0 physical. Invisible on the SOURCE path (the constructor
        // is never lowered to script) and reachable via `--ir`, where every
        // subsequent PICK/ROLL depth is off by one. Refusing beats inventing a
        // physical push for a call with no runtime meaning.
        if let ANFValue::Call { func, .. } = &binding.value {
            if func == "super" && method_name != "constructor" {
                return Err(format!(
                    "IR validation: super() is only valid in a constructor; method '{}' calls it. It emits no opcodes — the constructor args are already on the stack — so stack lowering pushes a model slot with no physical value, and every later PICK/ROLL depth in the method is off by one.",
                    method_name
                ));
            }
        }

        // R-126 / CL-BUG-164: add_output state-value arity.
        //
        // The source pipeline counts addOutput arity in the typechecker (the
        // N20 / N23 / N26 negatives). `--ir` runs no frontend, so such a node
        // reached stack lowering directly, and lower_add_output serializes the
        // OP_RETURN payload with the MIN of the two lists. Under-arity emitted
        // an output carrying fewer state fields than the contract has;
        // over-arity silently dropped the surplus. Measured through each tier's
        // own --ir CLI on a two-mutable-field contract (correct arity = 1394
        // hexchars): go, rust, zig, ruby, python and java ALL accepted,
        // emitting 1388 and 1396 hexchars respectively.
        //
        // CL-BUG-164 settled the cost: every SDK's StateSerializer writes ALL
        // mutable fields, so a short-payload continuation is spendable only by a
        // hand-crafted transaction, and the successor it produces is permanently
        // unspendable because the next call's deserialize_state slices at fixed
        // offsets. The message is shared verbatim with the other six tiers.
        if let ANFValue::AddOutput { state_values, .. } = &binding.value {
            if state_values.len() != mutable_count {
                return Err(format!(
                    "IR validation: add_output in method '{}' carries {} state values, but the contract declares {} mutable properties. The output's OP_RETURN payload is serialized from this list while deserialize_state slices the declared properties at fixed offsets, so any other count commits to a state payload no SDK-built transaction can produce and a successor that cannot be spent.",
                    method_name,
                    state_values.len(),
                    mutable_count
                ));
            }
        }

        // Validate nested bindings
        match &binding.value {
            ANFValue::If {
                then, else_branch, ..
            } => {
                validate_bindings(then, method_name, mutable_count)?;
                validate_bindings(else_branch, method_name, mutable_count)?;
            }
            ANFValue::Loop { count, body, start, .. } => {
                // N-133: `start` is `integer | "<decimal>n"`, and anything
                // else is refused HERE rather than substituted downstream.
                //
                // `lower_loop` read it as
                //
                //     match parse_const_value(start) {
                //         Some(ConstValue::Int(n)) => n,
                //         _ => BigInt::from(0),
                //     }
                //
                // and `parse_const_value` returns `ConstValue::Str` for any
                // string without the `n` suffix, so that arm swallowed `"5"`,
                // `"abc"`, `""`, `"5nn"`, a boolean and an explicit null alike
                // — every one of them becoming a zero-start loop that compiles
                // and exits 0.
                //
                // 0 is what made it invisible: a perfectly plausible loop
                // start, and the commonest one. `"5"` shows how bad the
                // substitution is — go, python, zig and ruby all read it as 5
                // while this tier read it as 0, and both sides exited 0 with a
                // well-formed script.
                //
                // The check sits at the loader, with the loop-count cap, so a
                // start that cannot be read never reaches codegen; the
                // `_ =>` arm in lower_loop is now unreachable rather than
                // load-bearing.
                match start {
                    serde_json::Value::Number(n) if n.is_i64() || n.is_u64() => {}
                    serde_json::Value::Number(_) => {
                        // A float is already refused at the door by N-131's
                        // lexical scan; a non-integral number reaching here
                        // would be an arbitrary-precision literal, which
                        // `parse_const_value` handles. Keep it accepted only
                        // when it really parses as an integer.
                        if crate::ir::parse_const_value(start).is_none() {
                            return Err(format!(
                                "IR validation: method {} binding {} has a loop start that is not an integer: {}",
                                method_name, binding.name, start
                            ));
                        }
                    }
                    serde_json::Value::String(s) => {
                        if !crate::ir::is_decimal_bigint_literal(s) {
                            return Err(format!(
                                "IR validation: method {} binding {} loop start: a string start must be the `<decimal>n` form, got {:?}",
                                method_name, binding.name, s
                            ));
                        }
                    }
                    other => {
                        return Err(format!(
                            "IR validation: method {} binding {} loop start: expected an integer or a `<decimal>n` string, got {}",
                            method_name, binding.name, other
                        ));
                    }
                }

                // N-115: the unroll ceiling, at the external-input trust
                // boundary.
                //
                // MAX_LOOP_COUNT is declared in THIS module and, until now, was
                // read only by frontend/anf_lower.rs — so it bounded loops
                // written in source and not one loop arriving as IR, in the
                // module that owns the constant. `count` is a `usize`, so a
                // ten-thousand-fold unroll is a perfectly well-typed value and
                // nothing downstream objects: the Rust tier accepted
                // count=10001 and emitted a 199734-hexchar (~97 KB) script.
                //
                // Cross-tier hex parity could not have caught this. Rust, Zig
                // and Java all accepted the same over-cap IR and all three
                // emitted the SAME bytes (sha256 e2c1be39...), so every parity
                // comparison among them passed; only Go, Python and Ruby
                // refused. The diagnostic below is Go's, word for word
                // (compilers/go/ir/loader.go), because the cheapest way to keep
                // six loaders answering alike is to say the same sentence.
                //
                // Negative counts need no check here: `usize` rules them out at
                // the type level, which is why Go's companion "negative loop
                // count" guard has no analogue in this arm.
                if *count > MAX_LOOP_COUNT as usize {
                    return Err(format!(
                        "IR validation: method {} binding {} has loop count {} exceeding maximum {}",
                        method_name, binding.name, count, MAX_LOOP_COUNT
                    ));
                }
                validate_bindings(body, method_name, mutable_count)?;
            }
            ANFValue::RawScript {
                bytes,
                in_arity,
                out_arity,
            } => {
                // N-113 / R-079: an empty span is a claim the emitter cannot
                // honour. Stack lowering models a raw_script purely from its
                // declared arities (it pops in_arity and pushes out_arity)
                // because the bytes are opaque to it, while emission writes
                // nothing at all for a zero-length span. The stack model and
                // the script then disagree, and every later PICK/ROLL depth
                // derived from that model addresses the wrong slot — the span
                // silently degrades to the identity function and a different
                // witness spends the output than the IR declared.
                //
                // The source path already rejects this ("asm() body must be a
                // non-empty hex string literal", frontend/validator.rs); --ir
                // is the same rule at the external-input trust boundary. All
                // empty bodies are rejected, including the degenerate
                // in=0/out=0 case, because mirroring the source validator
                // exactly is worth more than an arity-conditional rule that
                // would differ from the rule one pass earlier.
                if bytes.is_empty() {
                    return Err(format!(
                        "IR validation: method {} binding {} raw_script has an empty bytes body but declares in_arity {} / out_arity {}; a span that emits no bytes cannot have a stack effect",
                        method_name, binding.name, in_arity, out_arity
                    ));
                }
                // Opaque opcode-byte span — the bytes must be a well-formed
                // even-length hex string. in_arity / out_arity are usize, so
                // non-negativity is enforced at the type level.
                if bytes.len() % 2 != 0 {
                    return Err(format!(
                        "IR validation: method {} binding {} raw_script bytes have odd hex length {}",
                        method_name, binding.name, bytes.len()
                    ));
                }
                if !is_hex_string(bytes) {
                    return Err(format!(
                        "IR validation: method {} binding {} raw_script bytes contain non-hex characters",
                        method_name, binding.name
                    ));
                }
            }
            _ => {}
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{ANFMethod, ANFParam, ANFProgram, ANFProperty};

    // -----------------------------------------------------------------------
    // Valid minimal JSON
    // -----------------------------------------------------------------------

    #[test]
    fn test_load_ir_minimal_valid() {
        let json = r#"{
            "contractName": "P2PKH",
            "properties": [
                { "name": "pubKeyHash", "type": "Ripemd160", "readonly": true }
            ],
            "methods": [
                {
                    "name": "unlock",
                    "params": [
                        { "name": "sig", "type": "Sig" },
                        { "name": "pubKey", "type": "PubKey" }
                    ],
                    "body": [
                        { "name": "_t0", "value": { "kind": "load_param", "name": "sig" } },
                        { "name": "_t1", "value": { "kind": "load_param", "name": "pubKey" } },
                        { "name": "_t2", "value": { "kind": "call", "func": "checkSig", "args": ["_t0", "_t1"] } },
                        { "name": "_t3", "value": { "kind": "assert", "value": "_t2" } }
                    ],
                    "isPublic": true
                }
            ]
        }"#;
        let program = load_ir_from_str(json).expect("should parse valid minimal IR");
        assert_eq!(program.contract_name, "P2PKH");
        assert_eq!(program.properties.len(), 1);
        assert_eq!(program.properties[0].name, "pubKeyHash");
        assert_eq!(program.methods.len(), 1);
        assert_eq!(program.methods[0].name, "unlock");
        assert_eq!(program.methods[0].params.len(), 2);
        assert_eq!(program.methods[0].body.len(), 4);
    }

    #[test]
    fn test_load_ir_empty_methods_valid() {
        let json = r#"{
            "contractName": "Empty",
            "properties": [],
            "methods": [
                {
                    "name": "noop",
                    "params": [],
                    "body": [
                        { "name": "_t0", "value": { "kind": "load_const", "value": true } },
                        { "name": "_t1", "value": { "kind": "assert", "value": "_t0" } }
                    ],
                    "isPublic": true
                }
            ]
        }"#;
        let program = load_ir_from_str(json).expect("should parse empty-properties IR");
        assert_eq!(program.contract_name, "Empty");
        assert!(program.properties.is_empty());
    }

    #[test]
    fn test_load_ir_load_const_types() {
        let json = r#"{
            "contractName": "ConstTest",
            "properties": [],
            "methods": [
                {
                    "name": "test",
                    "params": [],
                    "body": [
                        { "name": "_t0", "value": { "kind": "load_const", "value": 42 } },
                        { "name": "_t1", "value": { "kind": "load_const", "value": true } },
                        { "name": "_t2", "value": { "kind": "load_const", "value": "deadbeef" } },
                        { "name": "_t3", "value": { "kind": "assert", "value": "_t1" } }
                    ],
                    "isPublic": true
                }
            ]
        }"#;
        let program = load_ir_from_str(json).expect("should parse various load_const types");
        let body = &program.methods[0].body;
        // Check int const
        if let ANFValue::LoadConst { value } = &body[0].value {
            assert_eq!(value.as_i64(), Some(42));
        } else {
            panic!("expected LoadConst for _t0");
        }
        // Check bool const
        if let ANFValue::LoadConst { value } = &body[1].value {
            assert_eq!(value.as_bool(), Some(true));
        } else {
            panic!("expected LoadConst for _t1");
        }
        // Check string const
        if let ANFValue::LoadConst { value } = &body[2].value {
            assert_eq!(value.as_str(), Some("deadbeef"));
        } else {
            panic!("expected LoadConst for _t2");
        }
    }

    // -----------------------------------------------------------------------
    // Validation errors
    // -----------------------------------------------------------------------

    #[test]
    fn test_load_ir_empty_contract_name_error() {
        let json = r#"{
            "contractName": "",
            "properties": [],
            "methods": []
        }"#;
        let err = load_ir_from_str(json).unwrap_err();
        assert!(
            err.contains("contractName is required"),
            "expected contractName error, got: {}",
            err
        );
    }

    #[test]
    fn test_load_ir_empty_property_name_error() {
        let json = r#"{
            "contractName": "Bad",
            "properties": [
                { "name": "", "type": "bigint", "readonly": true }
            ],
            "methods": []
        }"#;
        let err = load_ir_from_str(json).unwrap_err();
        assert!(
            err.contains("empty name"),
            "expected empty name error, got: {}",
            err
        );
    }

    #[test]
    fn test_load_ir_empty_property_type_error() {
        let json = r#"{
            "contractName": "Bad",
            "properties": [
                { "name": "x", "type": "", "readonly": true }
            ],
            "methods": []
        }"#;
        let err = load_ir_from_str(json).unwrap_err();
        assert!(
            err.contains("empty type"),
            "expected empty type error, got: {}",
            err
        );
    }

    #[test]
    fn test_load_ir_empty_method_name_error() {
        let json = r#"{
            "contractName": "Bad",
            "properties": [],
            "methods": [
                { "name": "", "params": [], "body": [], "isPublic": true }
            ]
        }"#;
        let err = load_ir_from_str(json).unwrap_err();
        assert!(
            err.contains("empty name"),
            "expected empty method name error, got: {}",
            err
        );
    }

    #[test]
    fn test_load_ir_empty_param_name_error() {
        let json = r#"{
            "contractName": "Bad",
            "properties": [],
            "methods": [
                {
                    "name": "test",
                    "params": [{ "name": "", "type": "bigint" }],
                    "body": [],
                    "isPublic": true
                }
            ]
        }"#;
        let err = load_ir_from_str(json).unwrap_err();
        assert!(
            err.contains("empty name"),
            "expected empty param name error, got: {}",
            err
        );
    }

    #[test]
    fn test_load_ir_empty_param_type_error() {
        let json = r#"{
            "contractName": "Bad",
            "properties": [],
            "methods": [
                {
                    "name": "test",
                    "params": [{ "name": "x", "type": "" }],
                    "body": [],
                    "isPublic": true
                }
            ]
        }"#;
        let err = load_ir_from_str(json).unwrap_err();
        assert!(
            err.contains("empty type"),
            "expected empty param type error, got: {}",
            err
        );
    }

    #[test]
    fn test_load_ir_empty_binding_name_error() {
        let json = r#"{
            "contractName": "Bad",
            "properties": [],
            "methods": [
                {
                    "name": "test",
                    "params": [],
                    "body": [
                        { "name": "", "value": { "kind": "load_const", "value": 1 } }
                    ],
                    "isPublic": true
                }
            ]
        }"#;
        let err = load_ir_from_str(json).unwrap_err();
        assert!(
            err.contains("empty name"),
            "expected empty binding name error, got: {}",
            err
        );
    }

    #[test]
    fn test_load_ir_invalid_json_error() {
        let json = "{ this is not valid json }";
        let err = load_ir_from_str(json).unwrap_err();
        assert!(
            err.contains("invalid IR JSON"),
            "expected JSON parse error, got: {}",
            err
        );
    }

    #[test]
    fn test_load_ir_unknown_kind_in_json() {
        // serde(tag = "kind") will fail to deserialize an unknown kind variant
        let json = r#"{
            "contractName": "Bad",
            "properties": [],
            "methods": [
                {
                    "name": "test",
                    "params": [],
                    "body": [
                        { "name": "_t0", "value": { "kind": "unknown_kind_xyz" } }
                    ],
                    "isPublic": true
                }
            ]
        }"#;
        let err = load_ir_from_str(json).unwrap_err();
        // serde rejects unrecognized "kind" tags at the deserialization level.
        //
        // R-177: this used to assert `err.contains("invalid IR JSON")`, and
        // that assertion was the evidence the finding cited that the loader's
        // own KNOWN_KINDS branch never fired. The rejection still happens in
        // serde — that part was never wrong — but the message now leads with
        // the wording the other six tiers use, so a caller can grep one string
        // across all seven.
        assert!(
            err.contains("unknown ANF kind"),
            "expected the shared wording for an unknown kind, got: {}",
            err
        );
        assert!(
            err.contains("unknown_kind_xyz"),
            "expected the offending kind to be quoted, got: {}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // Round-trip: construct -> serialize -> load
    // -----------------------------------------------------------------------

    #[test]
    fn test_round_trip_serialize_deserialize() {
        let program = ANFProgram {
            contract_name: "RoundTrip".to_string(),
            parent_class: String::new(),
            properties: vec![ANFProperty {
                name: "count".to_string(),
                prop_type: "bigint".to_string(),
                readonly: false,
                initial_value: None,
                synthetic_array_chain: None,
            }],
            methods: vec![ANFMethod {
                name: "increment".to_string(),
                params: vec![ANFParam {
                    name: "amount".to_string(),
                    param_type: "bigint".to_string(),
                }],
                body: vec![
                    ANFBinding {
                        name: "_t0".to_string(),
                        value: ANFValue::LoadParam {
                            name: "amount".to_string(),
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "_t1".to_string(),
                        value: ANFValue::LoadProp {
                            name: "count".to_string(),
                            preserve: false,
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "_t2".to_string(),
                        value: ANFValue::BinOp {
                            op: "+".to_string(),
                            left: "_t1".to_string(),
                            right: "_t0".to_string(),
                            result_type: Some("bigint".to_string()),
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "_t3".to_string(),
                        value: ANFValue::UpdateProp {
                            name: "count".to_string(),
                            value: "_t2".to_string(),
                        },
                        source_loc: None,
                    },
                ],
                is_public: true,
                sighash_type: None,
            }],
        };

        let json = serde_json::to_string(&program).expect("serialization should succeed");
        let loaded = load_ir_from_str(&json).expect("round-trip load should succeed");

        assert_eq!(loaded.contract_name, "RoundTrip");
        assert_eq!(loaded.properties.len(), 1);
        assert_eq!(loaded.properties[0].name, "count");
        assert!(!loaded.properties[0].readonly);
        assert_eq!(loaded.methods.len(), 1);
        assert_eq!(loaded.methods[0].name, "increment");
        assert_eq!(loaded.methods[0].params.len(), 1);
        assert_eq!(loaded.methods[0].body.len(), 4);

        // Verify specific binding kinds survived the round-trip
        assert!(matches!(&loaded.methods[0].body[0].value, ANFValue::LoadParam { name } if name == "amount"));
        assert!(matches!(&loaded.methods[0].body[1].value, ANFValue::LoadProp { name, .. } if name == "count"));
        assert!(matches!(&loaded.methods[0].body[2].value, ANFValue::BinOp { op, .. } if op == "+"));
        assert!(matches!(&loaded.methods[0].body[3].value, ANFValue::UpdateProp { name, .. } if name == "count"));
    }

    #[test]
    fn test_round_trip_with_initial_value() {
        let program = ANFProgram {
            contract_name: "InitTest".to_string(),
            parent_class: String::new(),
            properties: vec![ANFProperty {
                name: "value".to_string(),
                prop_type: "bigint".to_string(),
                readonly: true,
                initial_value: Some(serde_json::json!(100)),
                synthetic_array_chain: None,
            }],
            methods: vec![ANFMethod {
                name: "check".to_string(),
                params: vec![],
                body: vec![
                    ANFBinding {
                        name: "_t0".to_string(),
                        value: ANFValue::LoadConst {
                            value: serde_json::json!(true),
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "_t1".to_string(),
                        value: ANFValue::Assert {
                            value: "_t0".to_string(),
                            is_auto_injected_state_check: false,
                        },
                        source_loc: None,
                    },
                ],
                is_public: true,
                sighash_type: None,
            }],
        };

        let json = serde_json::to_string(&program).expect("serialization should succeed");
        let loaded = load_ir_from_str(&json).expect("round-trip load should succeed");

        assert_eq!(loaded.properties[0].initial_value, Some(serde_json::json!(100)));
    }

    /// N-115 — the unroll ceiling on the `--ir` path.
    ///
    /// `MAX_LOOP_COUNT` is declared in this module but, before the fix, was
    /// read only by `frontend/anf_lower.rs` — the SOURCE path. A loop arriving
    /// as IR was bounded by nothing: `count` is a `usize`, so 10001 is a
    /// perfectly well-typed value, and this tier emitted a 199734-hexchar
    /// (~97 KB) script for it.
    ///
    /// Measured against the checked-in `bounded-loop` golden: Go, Python and
    /// Ruby rejected count=10001; Rust, Zig and Java accepted it and all three
    /// emitted the SAME bytes, which is exactly why cross-tier hex parity was
    /// blind to it. `conformance/negatives/ir/I07-loop-count-over-max.ir.json`
    /// is that golden with this one field changed.
    ///
    /// The control is deliberate: a probe whose control also fails proves
    /// nothing, so the at-the-limit case must be observed LOADING before the
    /// over-the-limit case's refusal means anything.
    fn loop_count_program(count: usize) -> String {
        let program = ANFProgram {
            contract_name: "Bounded".to_string(),
            parent_class: String::new(),
            properties: vec![],
            methods: vec![ANFMethod {
                name: "unlock".to_string(),
                params: vec![],
                body: vec![ANFBinding {
                    name: "_loop".to_string(),
                    value: ANFValue::Loop {
                        count,
                        body: vec![ANFBinding {
                            name: "_lb".to_string(),
                            value: ANFValue::LoadConst {
                                value: serde_json::json!(0),
                            },
                            source_loc: None,
                        }],
                        iter_var: "i".to_string(),
                        start: serde_json::json!(0),
                        step: 1,
                    },
                    source_loc: None,
                }],
                is_public: true,
                sighash_type: None,
            }],
        };
        serde_json::to_string(&program).expect("serialization should succeed")
    }

    #[test]
    fn control_loop_count_at_the_limit_still_loads() {
        let loaded = load_ir_from_str(&loop_count_program(MAX_LOOP_COUNT as usize))
            .expect("a loop count exactly at MAX_LOOP_COUNT is legal and must still load");
        assert_eq!(loaded.contract_name, "Bounded");
    }

    #[test]
    fn rejects_loop_count_over_max() {
        let err = load_ir_from_str(&loop_count_program(MAX_LOOP_COUNT as usize + 1))
            .expect_err("a loop count above MAX_LOOP_COUNT must be refused on the --ir path");
        assert!(
            err.contains("loop count 10001 exceeding maximum 10000"),
            "diagnostic must name the count and the limit, as Go's does: {err}"
        );
    }

    #[test]
    fn test_round_trip_if_and_loop() {
        let program = ANFProgram {
            contract_name: "Nested".to_string(),
            parent_class: String::new(),
            properties: vec![],
            methods: vec![ANFMethod {
                name: "test".to_string(),
                params: vec![],
                body: vec![
                    ANFBinding {
                        name: "_cond".to_string(),
                        value: ANFValue::LoadConst {
                            value: serde_json::json!(true),
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "_if".to_string(),
                        value: ANFValue::If {
                            cond: "_cond".to_string(),
                            then: vec![ANFBinding {
                                name: "_t".to_string(),
                                value: ANFValue::LoadConst {
                                    value: serde_json::json!(1),
                                },
                                source_loc: None,
                            }],
                            else_branch: vec![ANFBinding {
                                name: "_e".to_string(),
                                value: ANFValue::LoadConst {
                                    value: serde_json::json!(2),
                                },
                                source_loc: None,
                            }],
                            results: Vec::new(),
                        },
                        source_loc: None,
                    },
                    ANFBinding {
                        name: "_loop".to_string(),
                        value: ANFValue::Loop {
                            count: 5,
                            body: vec![ANFBinding {
                                name: "_lb".to_string(),
                                value: ANFValue::LoadConst {
                                    value: serde_json::json!(0),
                                },
                                source_loc: None,
                            }],
                            iter_var: "i".to_string(),
                            start: serde_json::json!(0),
                            step: 1,
                        },
                        source_loc: None,
                    },
                ],
                is_public: true,
                sighash_type: None,
            }],
        };

        let json = serde_json::to_string(&program).expect("serialization should succeed");
        let loaded = load_ir_from_str(&json).expect("round-trip load should succeed");

        // Verify If survived
        if let ANFValue::If { cond, then, else_branch, .. } = &loaded.methods[0].body[1].value {
            assert_eq!(cond, "_cond");
            assert_eq!(then.len(), 1);
            assert_eq!(else_branch.len(), 1);
        } else {
            panic!("expected If binding");
        }

        // Verify Loop survived
        if let ANFValue::Loop { count, body, iter_var, start, step } = &loaded.methods[0].body[2].value {
            assert_eq!(*count, 5);
            assert_eq!(body.len(), 1);
            assert_eq!(iter_var, "i");
            assert_eq!(*start, serde_json::json!(0));
            assert_eq!(*step, 1);
        } else {
            panic!("expected Loop binding");
        }
    }

    // -----------------------------------------------------------------------
    // I9: loadIR — empty param type rejected
    // Method param with `type: ""` → Err result
    // -----------------------------------------------------------------------

    #[test]
    fn test_i9_load_ir_empty_param_type_rejected() {
        let json = r#"{
            "contractName": "Bad",
            "properties": [],
            "methods": [
                {
                    "name": "test",
                    "params": [{ "name": "x", "type": "" }],
                    "body": [
                        { "name": "_t0", "value": { "kind": "load_const", "value": true } },
                        { "name": "_t1", "value": { "kind": "assert", "value": "_t0" } }
                    ],
                    "isPublic": true
                }
            ]
        }"#;
        let result = load_ir_from_str(json);
        assert!(
            result.is_err(),
            "method param with empty type should produce an Err; got: {:?}",
            result.ok()
        );
        let err = result.unwrap_err();
        assert!(
            err.contains("empty type") || err.contains("type") || err.contains("param"),
            "error should mention empty type or param; got: {}",
            err
        );
    }

    // -----------------------------------------------------------------------
    // N-113 — the two shapes the Go tier rejected alone (R-079 / R-081)
    //
    // Both are `--ir`-only: the source path refuses each shape in
    // frontend/validator.rs, and validate_ir is reachable only from the IR
    // loader. Go grew these guards first (compilers/go/ir/loader.go) and was
    // deliberately, transiently stricter than its six peers until N-113;
    // conformance/negatives/ir-rejection-parity.test.ts is the gate that now
    // compares the six.
    // -----------------------------------------------------------------------

    /// A one-method contract, parameterised on the two fields under test, so
    /// every case below differs from the VALID control in exactly one way.
    fn ir_with(is_public: bool, raw_bytes: &str) -> String {
        format!(
            r#"{{
                "contractName": "Anyone",
                "properties": [],
                "methods": [
                    {{
                        "name": "unlock",
                        "params": [],
                        "isPublic": {},
                        "body": [
                            {{ "name": "t0", "value": {{
                                "kind": "raw_script",
                                "bytes": "{}",
                                "in_arity": 0,
                                "out_arity": 1
                            }} }}
                        ]
                    }}
                ]
            }}"#,
            is_public, raw_bytes
        )
    }

    #[test]
    fn test_control_valid_ir_is_accepted() {
        // The control both cases below are derived from. A probe whose control
        // also fails proves nothing.
        assert!(
            load_ir_from_str(&ir_with(true, "51")).is_ok(),
            "the control must load, or neither rejection below means anything"
        );
    }

    #[test]
    fn test_rejects_empty_raw_script_body() {
        // R-079: lowering pops in_arity and pushes out_arity on the stack model
        // while emission writes nothing for a zero-length span. The span
        // degrades to the identity function and a DIFFERENT WITNESS spends the
        // output. Measured on @bsv/sdk's Spend: `8f01859c` accepts x=5 and
        // rejects x=-5; with the body erased, `01859c` does the opposite.
        let err = load_ir_from_str(&ir_with(true, ""))
            .expect_err("an empty raw_script body must be rejected");
        assert!(
            err.contains("empty bytes body"),
            "error should name the empty body; got: {}",
            err
        );
    }

    #[test]
    fn test_rejects_empty_raw_script_body_even_at_zero_arity() {
        // The degenerate in=0/out=0 case is harmless on its own, and is
        // rejected anyway: mirroring the source validator exactly beats a
        // narrower arity-conditional rule that would differ from the rule one
        // pass earlier. Same judgment call as the Go tier's.
        let json = r#"{
            "contractName": "Anyone",
            "properties": [],
            "methods": [
                {
                    "name": "unlock",
                    "params": [],
                    "isPublic": true,
                    "body": [
                        { "name": "t0", "value": {
                            "kind": "raw_script", "bytes": "", "in_arity": 0, "out_arity": 0
                        } }
                    ]
                }
            ]
        }"#;
        assert!(load_ir_from_str(json).is_err());
    }

    #[test]
    fn test_rejects_no_public_methods() {
        // R-081: emission succeeds with an EMPTY locking script, which is
        // anyone-can-spend. On @bsv/sdk's Spend under full consensus wrappers,
        // lock="" with unlock=OP_1 (0x51) validates.
        let err = load_ir_from_str(&ir_with(false, "51"))
            .expect_err("a contract with no public method must be rejected");
        assert!(
            err.contains("no public methods"),
            "error should name the missing entry point; got: {}",
            err
        );
    }

    #[test]
    fn test_rejects_empty_method_list() {
        let json = r#"{ "contractName": "Empty", "properties": [], "methods": [] }"#;
        let err = load_ir_from_str(json).expect_err("no methods at all must be rejected");
        assert!(err.contains("no public methods"), "got: {}", err);
    }

    #[test]
    fn test_structural_errors_keep_priority_over_the_entry_point_error() {
        // Ordering matters and is asserted, not assumed: when a binding is ALSO
        // malformed, the malformed binding is the more actionable diagnostic.
        // Same ordering as compilers/go/ir/loader.go.
        let json = r#"{
            "contractName": "Anyone",
            "properties": [],
            "methods": [
                {
                    "name": "unlock",
                    "params": [],
                    "isPublic": false,
                    "body": [
                        { "name": "t0", "value": {
                            "kind": "raw_script", "bytes": "515", "in_arity": 0, "out_arity": 1
                        } }
                    ]
                }
            ]
        }"#;
        let err = load_ir_from_str(json).expect_err("must be rejected");
        assert!(
            err.contains("odd hex length"),
            "the structural error should win; got: {}",
            err
        );
    }
}
