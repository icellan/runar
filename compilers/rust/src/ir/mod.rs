//! ANF IR types and loader.
//!
//! These types mirror the canonical Rúnar ANF IR JSON schema. Any conformant
//! Rúnar compiler produces byte-identical ANF IR (when serialised with canonical
//! JSON), so these types serve as the universal interchange format.

pub mod input_limits;
pub mod loader;
pub mod required_fields;
pub mod synthetic_array_chain;
pub mod unknown_anf_kind_error;

pub use unknown_anf_kind_error::UnknownAnfKindError;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Source locations
// ---------------------------------------------------------------------------

/// Source location in the original file (used for debug source maps).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLocation {
    pub file: String,
    pub line: usize,
    pub column: usize,
}

// ---------------------------------------------------------------------------
// Program structure
// ---------------------------------------------------------------------------

/// Top-level ANF IR container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ANFProgram {
    #[serde(rename = "contractName")]
    pub contract_name: String,
    pub properties: Vec<ANFProperty>,
    pub methods: Vec<ANFMethod>,
    /// Base class the source contract extends ("SmartContract" |
    /// "StatefulSmartContract" | "UnsafeSmartContract"). F-038: wire data
    /// (`parentClass`, `$defs`-root of the shared JSON Schema), so an
    /// `--emit-ir` -> `--ir` round trip keeps it. The artifact assembler copies
    /// it to the top-level artifact field so SDKs can gate the issue-#42/#44
    /// terminal sighash subscript trim on the authoritative parent class (a
    /// StatefulSmartContract with zero mutable fields still needs the trim even
    /// though state_fields is empty). Empty = absent (IR written before F-038).
    #[serde(
        rename = "parentClass",
        skip_serializing_if = "String::is_empty",
        default,
        deserialize_with = "null_as_empty"
    )]
    pub parent_class: String,
}

/// One level of a synthetic-array chain attached to expanded leaf
/// properties produced by the expand-fixed-arrays pass. Outermost
/// level first.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ANFSyntheticArrayLevel {
    pub base: String,
    pub index: usize,
    pub length: usize,
}

/// A contract-level property (constructor parameter).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ANFProperty {
    pub name: String,
    #[serde(rename = "type")]
    pub prop_type: String,
    pub readonly: bool,
    #[serde(rename = "initialValue", skip_serializing_if = "Option::is_none")]
    pub initial_value: Option<serde_json::Value>,
    /// Non-empty for synthetic scalar leaves produced by the
    /// expand-fixed-arrays pass. Outermost level first. Used by the
    /// assembler to re-group these back into a single (possibly nested)
    /// FixedArray ABI/state entry.
    /// N-095: the wire spelling is `syntheticArrayChain`, matching the Go
    /// reference and `$defs.ANFProperty` in the shared JSON Schema. The
    /// `__`-prefixed form this used to emit is a TypeScript *AST* convention
    /// for compiler-internal annotations and has no business on the ANF wire.
    #[serde(rename = "syntheticArrayChain", skip_serializing_if = "Option::is_none", default)]
    pub synthetic_array_chain: Option<Vec<ANFSyntheticArrayLevel>>,
}

/// A single contract method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ANFMethod {
    pub name: String,
    pub params: Vec<ANFParam>,
    pub body: Vec<ANFBinding>,
    #[serde(rename = "isPublic")]
    pub is_public: bool,
    /// Issue #123: the method's declared `@sighash` type (e.g. `0x43` for
    /// SINGLE|FORKID), `None` for the default `ALL|FORKID`. F-065 / F-088:
    /// wire data (`sigHashType`), omitted for the default so directive-free
    /// ANF is unchanged; an `--emit-ir` -> `--ir` round trip keeps it. The
    /// artifact assembler copies a non-default value into
    /// `ABIMethod.sigHashType` so the SDK builds the matching preimage.
    #[serde(rename = "sigHashType", skip_serializing_if = "is_default_sighash", default)]
    pub sighash_type: Option<i64>,
}

/// A JSON `null` `parentClass` reads as absent, like every other loader.
fn null_as_empty<'de, D: serde::Deserializer<'de>>(d: D) -> Result<String, D::Error> {
    Ok(<Option<String> as serde::Deserialize>::deserialize(d)?.unwrap_or_default())
}

/// `sigHashType` is omitted for `None` and for the default ALL|FORKID (0x41).
fn is_default_sighash(v: &Option<i64>) -> bool {
    matches!(v, None | Some(0x41))
}

/// A method parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ANFParam {
    pub name: String,
    #[serde(rename = "type")]
    pub param_type: String,
}

// ---------------------------------------------------------------------------
// Bindings
// ---------------------------------------------------------------------------

/// A single let-binding: `let <name> = <value>`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ANFBinding {
    pub name: String,
    pub value: ANFValue,
    /// Debug-only: source location of the originating AST node. Not part of conformance.
    #[serde(rename = "sourceLoc", skip_serializing_if = "Option::is_none")]
    pub source_loc: Option<SourceLocation>,
}

// ---------------------------------------------------------------------------
// ANF value types (discriminated on `kind`)
// ---------------------------------------------------------------------------

/// Default `Loop::start` for IR payloads that predate issue #121: a zero-start
/// counting-up loop (`i = 0..count-1`).
fn default_loop_start() -> serde_json::Value {
    serde_json::Value::Number(serde_json::Number::from(0))
}

/// Default `Loop::step` for IR payloads that predate issue #121: +1 (counting up).
fn default_loop_step() -> i64 {
    1
}

/// Discriminated union of all ANF value types.
///
/// Uses `#[serde(tag = "kind")]` to match the JSON `"kind"` discriminator.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum ANFValue {
    #[serde(rename = "load_param")]
    LoadParam { name: String },

    #[serde(rename = "load_prop")]
    LoadProp {
        name: String,
        /// Issue #109 (`@embedAlways`): when true, dead-binding DCE must NOT
        /// remove this binding even though nothing references it. Set only on
        /// the `load_prop` that ANF lowering injects for an `@embedAlways`
        /// readonly field. In-memory only — never serialized, so the cross-tier
        /// ANF IR JSON stays byte-identical (matches the Zig reference in
        /// `compilers/zig/src/ir/types.zig`).
        #[serde(default, skip)]
        preserve: bool,
    },

    #[serde(rename = "load_const")]
    LoadConst { value: serde_json::Value },

    #[serde(rename = "bin_op")]
    BinOp {
        op: String,
        left: String,
        right: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        result_type: Option<String>,
    },

    #[serde(rename = "unary_op")]
    UnaryOp {
        op: String,
        operand: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        result_type: Option<String>,
    },

    #[serde(rename = "call")]
    Call {
        func: String,
        args: Vec<String>,
    },

    #[serde(rename = "method_call")]
    MethodCall {
        object: String,
        method: String,
        args: Vec<String>,
    },

    #[serde(rename = "if")]
    If {
        cond: String,
        then: Vec<ANFBinding>,
        #[serde(rename = "else")]
        else_branch: Vec<ANFBinding>,
        /// Ordered named result slots both arms leave (`results[0]` deepest).
        /// Entries name a branch-merged local or an arm-written contract
        /// property; stack lowering tells the two apart from the contract's
        /// property list, so the wire format stays a plain array of strings.
        /// Absent (not empty) when the `if` carries at most one result — see
        /// the TypeScript reference in
        /// `packages/runar-compiler/src/ir/anf-ir.ts` for the full contract.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        results: Vec<String>,
    },

    #[serde(rename = "loop")]
    Loop {
        count: usize,
        body: Vec<ANFBinding>,
        #[serde(rename = "iterVar")]
        iter_var: String,
        // Iterator start value and step direction (issue #121). The loop is
        // unrolled `count` times; on iteration `i` (0-based) the iterator
        // variable holds `start + i * step`. Zero-start counting-up loops carry
        // `start = 0` and `step = 1`, reproducing the historical
        // `i = 0..count-1` lowering byte-for-byte. Countdown loops carry
        // `step = -1`. Serialised as a JS-style decimal (number or `Nn`
        // string) via `bigint_to_json`; older payloads without the fields
        // default to a zero-start counting-up loop.
        #[serde(default = "default_loop_start")]
        start: serde_json::Value,
        #[serde(default = "default_loop_step")]
        step: i64,
    },

    #[serde(rename = "assert")]
    Assert {
        value: String,
        // Optional marker: set to `true` only on the auto-injected
        // `hash256(continuationOutputs) === extractOutputHash(txPreimage)`
        // assert emitted by the StatefulSmartContract lowering. Off-chain
        // SDK interpreters use this to skip the equality check without
        // resorting to positional or structural heuristics that misfire on
        // developer-written covenant asserts whose IR shape is identical.
        // Absent => developer code.
        #[serde(
            rename = "isAutoInjectedStateCheck",
            default,
            skip_serializing_if = "std::ops::Not::not"
        )]
        is_auto_injected_state_check: bool,
    },

    #[serde(rename = "update_prop")]
    UpdateProp { name: String, value: String },

    #[serde(rename = "get_state_script")]
    GetStateScript {},

    #[serde(rename = "check_preimage")]
    CheckPreimage {
        preimage: String,
        /// Issue #123: BIP-143 sighash flag the on-chain OP_PUSH_TX binding
        /// appends to the derived signature. Absent = default `ALL|FORKID`
        /// (0x41), byte-identical to the pinned cross-tier binding blob. Only
        /// set for a method that declares a non-default `@sighash` mode, so
        /// golden ANF stays unchanged for every existing contract.
        #[serde(rename = "sighashFlag", skip_serializing_if = "Option::is_none", default)]
        sighash_flag: Option<i64>,
    },

    #[serde(rename = "deserialize_state")]
    DeserializeState { preimage: String },

    #[serde(rename = "add_output")]
    AddOutput {
        satoshis: String,
        #[serde(rename = "stateValues")]
        state_values: Vec<String>,
        #[serde(default)]
        preimage: String,
    },

    #[serde(rename = "add_raw_output")]
    AddRawOutput {
        satoshis: String,
        #[serde(rename = "scriptBytes")]
        script_bytes: String,
    },

    /// AddDataOutput — records an additional transaction output that is NOT a
    /// state continuation. The output is included in the auto-computed
    /// continuation hash in declaration order, after state outputs and before
    /// the change output. The emit shape is identical to `add_raw_output`:
    /// amount(8LE) + varint(scriptLen) + scriptBytes.
    #[serde(rename = "add_data_output")]
    AddDataOutput {
        satoshis: String,
        #[serde(rename = "scriptBytes")]
        script_bytes: String,
    },

    #[serde(rename = "array_literal")]
    ArrayLiteral {
        elements: Vec<String>,
    },

    /// RawScript — an opaque opcode-byte span emitted verbatim by the `asm`
    /// compiler intrinsic. `bytes` is an even-length hex string of raw Bitcoin
    /// Script opcode bytes; `in_arity` / `out_arity` declare the span's stack
    /// effect. The bytes are never inspected — the peephole optimizer treats
    /// the span as a hard barrier and constant folding never crosses it.
    #[serde(rename = "raw_script")]
    RawScript {
        bytes: String,
        #[serde(rename = "in_arity")]
        in_arity: usize,
        #[serde(rename = "out_arity")]
        out_arity: usize,
    },
}

// ---------------------------------------------------------------------------
// Constant value helpers
// ---------------------------------------------------------------------------

/// Typed constant value extracted from a `serde_json::Value`.
#[derive(Debug, Clone)]
pub enum ConstValue {
    Bool(bool),
    /// Arbitrary-precision integer constant.
    ///
    /// Widened from `i128` to `num_bigint::BigInt` so 256-bit constants
    /// (e.g. the secp256k1 group order in schnorr-zkp's s-bound assert)
    /// round-trip through the IR JSON ↔ stack-IR boundary without
    /// truncation. Mirrors Go's `ConstBigInt *big.Int` field on
    /// `ANFValue`.
    Int(num_bigint::BigInt),
    Str(String),
}

impl ANFValue {
    /// Extract the typed constant from a `LoadConst` value.
    pub fn const_value(&self) -> Option<ConstValue> {
        match self {
            ANFValue::LoadConst { value } => parse_const_value(value),
            _ => None,
        }
    }
}

/// Reports whether `s` is a JS-style decimal `BigInt` literal: an optional
/// leading `-`, one or more ASCII digits, and a required trailing `n`.
///
/// Mirrors:
///   - Go: `compilers/go/ir/types.go::isDecimalBigIntLiteral` — the
///     discriminator the Go IR decoder uses to distinguish a decimal
///     `BigInt` from a hex-encoded `ByteString` in `load_const` JSON
///     strings.
///   - Python: `_is_decimal_bigint_literal`
///   - TS: the conformance runner's BigInt canonicalisation
///
/// Without the `n` suffix the two cases are indistinguishable when the
/// literal is all-digit (e.g. `"3030"` is both a valid decimal integer
/// AND a valid hex bytestring).
pub fn is_decimal_bigint_literal(s: &str) -> bool {
    let bytes = s.as_bytes();
    if bytes.len() < 2 || *bytes.last().unwrap() != b'n' {
        return false;
    }
    let start = if bytes[0] == b'-' { 1 } else { 0 };
    let body = &bytes[start..bytes.len() - 1];
    if body.is_empty() {
        return false;
    }
    body.iter().all(|c| c.is_ascii_digit())
}

/// Parse a `serde_json::Value` into a `ConstValue`.
///
/// `load_const` values arrive in one of four shapes:
/// - `true` / `false`                       → `ConstValue::Bool`
/// - JSON number (any precision)            → `ConstValue::Int(BigInt)`
/// - JSON string with trailing `n` suffix   → `ConstValue::Int(BigInt)`
///   (JS-style decimal BigInt; cross-tier oversize-int encoding)
/// - JSON string otherwise                  → `ConstValue::Str` (hex bytes)
pub fn parse_const_value(v: &serde_json::Value) -> Option<ConstValue> {
    use num_bigint::BigInt;
    use std::str::FromStr;
    match v {
        serde_json::Value::Bool(b) => Some(ConstValue::Bool(*b)),
        serde_json::Value::Number(n) => {
            // serde_json preserves integer JSON-number precision through
            // its string repr; parse via BigInt::from_str so 256-bit
            // values survive without truncation. JSON floats (e.g.
            // `1e20`) round-trip through a fractional string that
            // BigInt rejects.
            let s = n.to_string();
            if let Ok(bi) = BigInt::from_str(&s) {
                Some(ConstValue::Int(bi))
            } else if let Some(f) = n.as_f64() {
                if f.fract() == 0.0 {
                    // Integral-valued float: typically a bare integer too
                    // large for u64/i64 that serde_json (built without the
                    // `arbitrary_precision` feature) represents as f64 at
                    // PARSE time -- the digits are lost upstream of this
                    // function regardless of whether the original token had
                    // float syntax, so there is no way to refuse it here
                    // without also refusing legitimate oversize integers
                    // (R-017/CL-BUG-140's secp256k1-order fixture depends on
                    // this fallback staying lossy-but-accepting). Preserve
                    // the fallback for this shape, but convert the f64's
                    // ACTUAL value via `from_f64` rather than casting with
                    // `as i128`: a saturating cast clamps anything beyond
                    // `i128::MAX`/`MIN` to that bound, inventing a number
                    // the IR never contained (measured for `1e50`: pushes
                    // `i128::MAX` rather than refusing or converting). Still
                    // lossy above f64's ~53-bit mantissa, but no longer
                    // clamped to a fixed ceiling.
                    <BigInt as num_traits::FromPrimitive>::from_f64(f).map(ConstValue::Int)
                } else {
                    // A genuinely fractional magnitude (e.g. `1.5`) has no
                    // legal `load_const` value -- the ANF IR schema declares
                    // this field an integer. F-267 / CL-BUG-030: this used to
                    // fall through to the same `f as i128` cast above,
                    // silently truncating the fractional part into a WRONG
                    // integer (`1.5` -> `1`) instead of refusing it. Refuse
                    // it instead, same as every other undecodable
                    // `load_const` shape (see callers' `None` arms).
                    None
                }
            } else {
                None
            }
        }
        serde_json::Value::String(s) => {
            if is_decimal_bigint_literal(s) {
                // Strip the trailing 'n' and parse the digits as BigInt.
                let body = &s[..s.len() - 1];
                BigInt::from_str(body).ok().map(ConstValue::Int)
            } else {
                Some(ConstValue::Str(s.clone()))
            }
        }
        _ => None,
    }
}

/// Name prefix for the temporaries ANF lowering appends to BOTH arms of an
/// if-statement that merges two or more locals.
///
/// An `if` carries one value, so post-branch references to a merged local can
/// only be rewired by aliasing when there is exactly ONE of them. For two or
/// more, both arms instead end with an identical K-binding block — K copies
/// into `__merge$0..K-1`, then K rebinds of the locals from those temps —
/// which leaves the merged values on top in the same canonical order whichever
/// branch runs. Stack lowering recognises that trailing block by this prefix,
/// trims each arm down to the K results, and adopts them by name.
///
/// The prefix is part of the ANF wire format: all seven compilers emit and
/// recognise the same block.
pub const MERGED_LOCAL_TEMP_PREFIX: &str = "__merge$";

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// F-267 / CL-BUG-030: `parse_const_value` must REFUSE a genuinely
    /// fractional JSON number, not silently truncate it via `f64 as i128`.
    ///
    /// The `--ir` CLI/file/string entry points are already guarded against
    /// ANY float-syntax token (including integral ones like `1.0`) by
    /// N-131's `assert_no_json_floats` lexical pre-scan in
    /// `ir::loader::load_ir_from_str`/`load_ir_from_str_typed`, which runs
    /// on the raw bytes BEFORE `serde_json::from_str`. This test exercises
    /// `parse_const_value` directly on an in-memory `serde_json::Value`,
    /// which is the path a caller takes when it builds an `ANFProgram`
    /// itself and calls `compile_from_program` — bypassing the text-based
    /// loader (and its lexical guard) entirely. That path had no guard at
    /// all: the `Number` arm fell back to `BigInt::from(f as i128)`
    /// whenever `BigInt::from_str` failed on the number's string form,
    /// which happens for `1.5` just as it does for `1e50`.
    ///
    /// What this proves: given the float `1.5`, `parse_const_value` no
    /// longer invents a WRONG integer (previously `Some(ConstValue::Int(1))`
    /// — the fractional part silently dropped) — it returns `None`, matching
    /// the "undecodable load_const" panic path its callers (`lower_load_const`,
    /// `push_json_value`) already have wired up for `None`.
    ///
    /// What this does NOT prove: that every caller of `parse_const_value`
    /// now rejects a float end-to-end through the CLI (already covered by
    /// N-131's lexical pre-scan, not re-exercised here); nor that an
    /// INTEGRAL-valued float (e.g. `1.0`, or an oversize bare integer that
    /// overflowed to f64 at JSON-parse time) is rejected at this layer — see
    /// `test_parse_const_value_still_accepts_integral_oversize_float` below
    /// for why that distinction is deliberate, not an oversight.
    #[test]
    fn test_parse_const_value_rejects_fractional_float() {
        let v = serde_json::json!(1.5);
        assert!(
            parse_const_value(&v).is_none(),
            "parse_const_value silently truncated a fractional JSON float via f64-as-i128: got {:?}",
            parse_const_value(&v)
        );
    }

    /// Control: an INTEGRAL-valued float (fractional part exactly zero) must
    /// still decode, via the pre-existing lossy `f64 as i128` fallback.
    ///
    /// `serde_json`, built here without the `arbitrary_precision` feature,
    /// represents a bare integer literal too large for `u64`/`i64` as f64
    /// AT PARSE TIME — before `parse_const_value` ever sees it, and
    /// indistinguishably from a genuine `1.0`-style float token at the
    /// `serde_json::Value` level (both arrive as a float-backed `Number`
    /// whose `to_string()` contains a `.`/`e`). There is no way to refuse
    /// one without refusing the other here; only a lexical pre-scan of the
    /// raw JSON bytes (N-131, upstream of this function) can tell them apart.
    /// `bigint_initializer_encoding_tests.rs`
    /// (`ir_numeric_initial_value_matches_load_const_and_is_not_zero`)
    /// depends on the secp256k1-group-order-sized case staying accepted —
    /// lossy, but non-rejecting, a separate documented defect — so this
    /// fallback is preserved for `fract() == 0.0` values only.
    #[test]
    fn test_parse_const_value_still_accepts_integral_float() {
        let v = serde_json::json!(1e10);
        match parse_const_value(&v) {
            Some(ConstValue::Int(n)) => assert_eq!(n, num_bigint::BigInt::from(10_000_000_000i64)),
            other => panic!("expected Some(ConstValue::Int(10000000000)), got {:?}", other),
        }
    }

    /// F-267 (saturation half, per advisor follow-up): an integral-valued
    /// float whose magnitude exceeds `i128` must NOT saturate to
    /// `i128::MAX`. The N-131 header measured exactly this for `1e50` on the
    /// `--ir` boundary: `rust accept, SATURATED to i128::MAX (pushes
    /// 10ffff..7f)` — a value the IR never contained. `1e50` is
    /// `fract() == 0.0` (integral), so the previous `f as i128` cast ran and
    /// clamped instead of converting. `BigInt::from_f64` converts the f64's
    /// EXACT value instead of clamping, which is a no-op for anything within
    /// `i128` range (so `two_pow_60_initializer_emits_the_actual_value` and
    /// friends in `bigint_initializer_encoding_tests.rs` are unaffected) and
    /// stops inventing `i128::MAX` for anything beyond it.
    #[test]
    fn test_parse_const_value_oversize_integral_float_is_not_saturated() {
        let v = serde_json::json!(1e50);
        match parse_const_value(&v) {
            Some(ConstValue::Int(n)) => {
                assert_ne!(
                    n,
                    num_bigint::BigInt::from(i128::MAX),
                    "1e50 was clamped to i128::MAX instead of converted"
                );
                assert_eq!(
                    n,
                    <num_bigint::BigInt as num_traits::FromPrimitive>::from_f64(1e50_f64).unwrap()
                );
            }
            other => panic!("expected Some(ConstValue::Int(_)), got {:?}", other),
        }
    }

    /// Control: a genuine integer JSON number must still parse normally —
    /// the fix must not turn every number into a rejection.
    #[test]
    fn test_parse_const_value_accepts_plain_integer() {
        let v = serde_json::json!(42);
        match parse_const_value(&v) {
            Some(ConstValue::Int(n)) => assert_eq!(n, num_bigint::BigInt::from(42)),
            other => panic!("expected Some(ConstValue::Int(42)), got {:?}", other),
        }
    }
}
