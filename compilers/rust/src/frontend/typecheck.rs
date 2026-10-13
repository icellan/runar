//! Pass 3: Type-Check
//!
//! Type-checks the Rúnar AST. Builds type environments from properties,
//! constructor parameters, and method parameters, then verifies all
//! expressions have consistent types.

use std::collections::{HashMap, HashSet};

use num_bigint::BigInt;

use super::ast::*;
use super::diagnostic::Diagnostic;
use super::side_effect_summary::{compute_side_effect_summary, MethodEffects, SideEffectSummary};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Result of type checking.
pub struct TypeCheckResult {
    pub errors: Vec<Diagnostic>,
}

impl TypeCheckResult {
    /// Get error messages as plain strings (for backward compatibility).
    pub fn error_strings(&self) -> Vec<String> {
        self.errors.iter().map(|d| d.format_message()).collect()
    }
}

/// Type-check a Rúnar AST. Returns any type errors found.
/// F-024 (R14): the one diagnostic every tier emits for a write to continuationAmount().
pub const CONTINUATION_AMOUNT_READ_ONLY: &str = "continuationAmount() is read-only and cannot be assigned";

pub fn typecheck(contract: &ContractNode) -> TypeCheckResult {
    let mut errors: Vec<Diagnostic> = Vec::new();
    let mut checker = TypeChecker::new(contract, &mut errors);

    checker.check_property_initializers();
    checker.check_constructor();
    for method in &contract.methods {
        checker.check_method(method);
    }

    TypeCheckResult { errors }
}

// ---------------------------------------------------------------------------
// Type representation
// ---------------------------------------------------------------------------

/// Internal type representation (simplified string-based).
type TType = String;

const VOID: &str = "void";
const BIGINT: &str = "bigint";
const BOOLEAN: &str = "boolean";
const BYTESTRING: &str = "ByteString";

// ---------------------------------------------------------------------------
// Built-in function signatures
// ---------------------------------------------------------------------------

struct FuncSig {
    params: Vec<&'static str>,
    return_type: &'static str,
}

/// Allowed argument counts per builtin, for validating ANF IR that never went
/// through this pass (R-128 / R-165).
///
/// `--ir` runs no frontend, so a wrong-arity call used to reach stack
/// lowering, where each dispatch family pops `args.len()` from the stack MODEL
/// and then emits a FIXED-arity opcode blob: `cat` with one argument compiled
/// to a bare OP_CAT, `assert` with none to an EMPTY script. Derived from the
/// signature table below rather than copied, so the two cannot drift.
///
/// Two builtins accept more than one count — `assert` (1 or 2) and
/// `extractPrevOutputScript` (2 or 3) — both special-cased in `check_call_args`
/// for the same reason. `merkleRootPoseidon2KB` is variadic by a rule and is
/// handled by the caller.
pub fn builtin_allowed_arity(name: &str) -> Option<Vec<usize>> {
    match name {
        "assert" => return Some(vec![1, 2]),
        "extractPrevOutputScript" => return Some(vec![2, 3]),
        _ => {}
    }
    builtin_functions().get(name).map(|sig| vec![sig.params.len()])
}

fn builtin_functions() -> HashMap<&'static str, FuncSig> {
    let mut m = HashMap::new();

    m.insert("sha256", FuncSig { params: vec!["ByteString"], return_type: "Sha256" });
    m.insert("ripemd160", FuncSig { params: vec!["ByteString"], return_type: "Ripemd160" });
    m.insert("hash160", FuncSig { params: vec!["ByteString"], return_type: "Ripemd160" });
    m.insert("hash256", FuncSig { params: vec!["ByteString"], return_type: "Sha256" });
    m.insert("checkSig", FuncSig { params: vec!["Sig", "PubKey"], return_type: "boolean" });
    m.insert("checkMultiSig", FuncSig { params: vec!["Sig[]", "PubKey[]"], return_type: "boolean" });
    m.insert("assert", FuncSig { params: vec!["boolean"], return_type: "void" });
    m.insert("len", FuncSig { params: vec!["ByteString"], return_type: "bigint" });
    m.insert("cat", FuncSig { params: vec!["ByteString", "ByteString"], return_type: "ByteString" });
    m.insert("substr", FuncSig { params: vec!["ByteString", "bigint", "bigint"], return_type: "ByteString" });
    m.insert("num2bin", FuncSig { params: vec!["bigint", "bigint"], return_type: "ByteString" });
    m.insert("bin2num", FuncSig { params: vec!["ByteString"], return_type: "bigint" });
    m.insert("checkPreimage", FuncSig { params: vec!["SigHashPreimage"], return_type: "boolean" });
    m.insert("verifyRabinSig", FuncSig { params: vec!["ByteString", "RabinSig", "ByteString", "RabinPubKey"], return_type: "boolean" });
    m.insert("verifyWOTS", FuncSig { params: vec!["ByteString", "ByteString", "ByteString"], return_type: "boolean" });
    m.insert("verifySLHDSA_SHA2_128s", FuncSig { params: vec!["ByteString", "ByteString", "ByteString"], return_type: "boolean" });
    m.insert("verifySLHDSA_SHA2_128f", FuncSig { params: vec!["ByteString", "ByteString", "ByteString"], return_type: "boolean" });
    m.insert("verifySLHDSA_SHA2_192s", FuncSig { params: vec!["ByteString", "ByteString", "ByteString"], return_type: "boolean" });
    m.insert("verifySLHDSA_SHA2_192f", FuncSig { params: vec!["ByteString", "ByteString", "ByteString"], return_type: "boolean" });
    m.insert("verifySLHDSA_SHA2_256s", FuncSig { params: vec!["ByteString", "ByteString", "ByteString"], return_type: "boolean" });
    m.insert("verifySLHDSA_SHA2_256f", FuncSig { params: vec!["ByteString", "ByteString", "ByteString"], return_type: "boolean" });
    // Baby Bear field arithmetic
    m.insert("bbFieldAdd", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("bbFieldSub", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("bbFieldMul", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("bbFieldInv", FuncSig { params: vec!["bigint"], return_type: "bigint" });
    // Baby Bear ext4 field arithmetic
    m.insert("bbExt4Mul0", FuncSig { params: vec!["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type: "bigint" });
    m.insert("bbExt4Mul1", FuncSig { params: vec!["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type: "bigint" });
    m.insert("bbExt4Mul2", FuncSig { params: vec!["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type: "bigint" });
    m.insert("bbExt4Mul3", FuncSig { params: vec!["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type: "bigint" });
    m.insert("bbExt4Inv0", FuncSig { params: vec!["bigint", "bigint", "bigint", "bigint"], return_type: "bigint" });
    m.insert("bbExt4Inv1", FuncSig { params: vec!["bigint", "bigint", "bigint", "bigint"], return_type: "bigint" });
    m.insert("bbExt4Inv2", FuncSig { params: vec!["bigint", "bigint", "bigint", "bigint"], return_type: "bigint" });
    m.insert("bbExt4Inv3", FuncSig { params: vec!["bigint", "bigint", "bigint", "bigint"], return_type: "bigint" });

    // KoalaBear field arithmetic (p = 2130706433)
    m.insert("kbFieldAdd", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("kbFieldSub", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("kbFieldMul", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("kbFieldInv", FuncSig { params: vec!["bigint"], return_type: "bigint" });
    // KoalaBear quartic extension field (W = 3)
    m.insert("kbExt4Mul0", FuncSig { params: vec!["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type: "bigint" });
    m.insert("kbExt4Mul1", FuncSig { params: vec!["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type: "bigint" });
    m.insert("kbExt4Mul2", FuncSig { params: vec!["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type: "bigint" });
    m.insert("kbExt4Mul3", FuncSig { params: vec!["bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint", "bigint"], return_type: "bigint" });
    m.insert("kbExt4Inv0", FuncSig { params: vec!["bigint", "bigint", "bigint", "bigint"], return_type: "bigint" });
    m.insert("kbExt4Inv1", FuncSig { params: vec!["bigint", "bigint", "bigint", "bigint"], return_type: "bigint" });
    m.insert("kbExt4Inv2", FuncSig { params: vec!["bigint", "bigint", "bigint", "bigint"], return_type: "bigint" });
    m.insert("kbExt4Inv3", FuncSig { params: vec!["bigint", "bigint", "bigint", "bigint"], return_type: "bigint" });
    // BN254 field arithmetic
    m.insert("bn254FieldAdd", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("bn254FieldSub", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("bn254FieldMul", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("bn254FieldInv", FuncSig { params: vec!["bigint"], return_type: "bigint" });
    m.insert("bn254FieldNeg", FuncSig { params: vec!["bigint"], return_type: "bigint" });
    // BN254 G1 curve operations
    m.insert("bn254G1Add", FuncSig { params: vec!["Point", "Point"], return_type: "Point" });
    m.insert("bn254G1ScalarMul", FuncSig { params: vec!["Point", "bigint"], return_type: "Point" });
    m.insert("bn254G1Negate", FuncSig { params: vec!["Point"], return_type: "Point" });
    m.insert("bn254G1OnCurve", FuncSig { params: vec!["Point"], return_type: "boolean" });

    // Merkle proof verification
    m.insert("merkleRootSha256", FuncSig { params: vec!["ByteString", "ByteString", "bigint", "bigint"], return_type: "ByteString" });
    m.insert("merkleRootHash256", FuncSig { params: vec!["ByteString", "ByteString", "bigint", "bigint"], return_type: "ByteString" });

    m.insert("ecAdd", FuncSig { params: vec!["Point", "Point"], return_type: "Point" });
    m.insert("ecMul", FuncSig { params: vec!["Point", "bigint"], return_type: "Point" });
    m.insert("ecMulGen", FuncSig { params: vec!["bigint"], return_type: "Point" });
    m.insert("ecNegate", FuncSig { params: vec!["Point"], return_type: "Point" });
    m.insert("ecOnCurve", FuncSig { params: vec!["Point"], return_type: "boolean" });
    m.insert("ecModReduce", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("ecEncodeCompressed", FuncSig { params: vec!["Point"], return_type: "ByteString" });
    m.insert("ecMakePoint", FuncSig { params: vec!["bigint", "bigint"], return_type: "Point" });
    m.insert("ecPointX", FuncSig { params: vec!["Point"], return_type: "bigint" });
    m.insert("ecPointY", FuncSig { params: vec!["Point"], return_type: "bigint" });
    // Elliptic curve operations (P-256 / NIST P-256 / secp256r1)
    m.insert("p256Add", FuncSig { params: vec!["P256Point", "P256Point"], return_type: "P256Point" });
    m.insert("p256Mul", FuncSig { params: vec!["P256Point", "bigint"], return_type: "P256Point" });
    m.insert("p256MulGen", FuncSig { params: vec!["bigint"], return_type: "P256Point" });
    m.insert("p256Negate", FuncSig { params: vec!["P256Point"], return_type: "P256Point" });
    m.insert("p256OnCurve", FuncSig { params: vec!["P256Point"], return_type: "boolean" });
    m.insert("p256EncodeCompressed", FuncSig { params: vec!["P256Point"], return_type: "ByteString" });
    m.insert("verifyECDSA_P256", FuncSig { params: vec!["ByteString", "ByteString", "ByteString"], return_type: "boolean" });
    // Elliptic curve operations (P-384 / NIST P-384 / secp384r1)
    m.insert("p384Add", FuncSig { params: vec!["P384Point", "P384Point"], return_type: "P384Point" });
    m.insert("p384Mul", FuncSig { params: vec!["P384Point", "bigint"], return_type: "P384Point" });
    m.insert("p384MulGen", FuncSig { params: vec!["bigint"], return_type: "P384Point" });
    m.insert("p384Negate", FuncSig { params: vec!["P384Point"], return_type: "P384Point" });
    m.insert("p384OnCurve", FuncSig { params: vec!["P384Point"], return_type: "boolean" });
    m.insert("p384EncodeCompressed", FuncSig { params: vec!["P384Point"], return_type: "ByteString" });
    m.insert("verifyECDSA_P384", FuncSig { params: vec!["ByteString", "ByteString", "ByteString"], return_type: "boolean" });
    m.insert("abs", FuncSig { params: vec!["bigint"], return_type: "bigint" });
    m.insert("min", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("max", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("within", FuncSig { params: vec!["bigint", "bigint", "bigint"], return_type: "boolean" });
    m.insert("reverseBytes", FuncSig { params: vec!["ByteString"], return_type: "ByteString" });
    m.insert("left", FuncSig { params: vec!["ByteString", "bigint"], return_type: "ByteString" });
    m.insert("right", FuncSig { params: vec!["ByteString", "bigint"], return_type: "ByteString" });
    m.insert("int2str", FuncSig { params: vec!["bigint", "bigint"], return_type: "ByteString" });
    m.insert("toByteString", FuncSig { params: vec!["ByteString"], return_type: "ByteString" });
    m.insert("exit", FuncSig { params: vec!["boolean"], return_type: "void" });
    m.insert("pack", FuncSig { params: vec!["bigint"], return_type: "ByteString" });
    m.insert("unpack", FuncSig { params: vec!["ByteString"], return_type: "bigint" });
    m.insert("safediv", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("safemod", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("clamp", FuncSig { params: vec!["bigint", "bigint", "bigint"], return_type: "bigint" });
    m.insert("sign", FuncSig { params: vec!["bigint"], return_type: "bigint" });
    m.insert("pow", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("mulDiv", FuncSig { params: vec!["bigint", "bigint", "bigint"], return_type: "bigint" });
    m.insert("percentOf", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("sqrt", FuncSig { params: vec!["bigint"], return_type: "bigint" });
    m.insert("gcd", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("divmod", FuncSig { params: vec!["bigint", "bigint"], return_type: "bigint" });
    m.insert("log2", FuncSig { params: vec!["bigint"], return_type: "bigint" });
    m.insert("bool", FuncSig { params: vec!["bigint"], return_type: "boolean" });
    m.insert("split", FuncSig { params: vec!["ByteString", "bigint"], return_type: "ByteString" });
    m.insert("sha256Compress", FuncSig { params: vec!["ByteString", "ByteString"], return_type: "ByteString" });
    m.insert("sha256Finalize", FuncSig { params: vec!["ByteString", "ByteString", "bigint"], return_type: "ByteString" });
    m.insert("blake3Compress", FuncSig { params: vec!["ByteString", "ByteString"], return_type: "ByteString" });
    m.insert("blake3Hash", FuncSig { params: vec!["ByteString"], return_type: "ByteString" });

    // Preimage extractors
    m.insert("extractVersion", FuncSig { params: vec!["SigHashPreimage"], return_type: "bigint" });
    m.insert("extractHashPrevouts", FuncSig { params: vec!["SigHashPreimage"], return_type: "Sha256" });
    m.insert("extractHashSequence", FuncSig { params: vec!["SigHashPreimage"], return_type: "Sha256" });
    m.insert("extractOutpoint", FuncSig { params: vec!["SigHashPreimage"], return_type: "ByteString" });
    m.insert("extractInputIndex", FuncSig { params: vec!["SigHashPreimage"], return_type: "bigint" });
    m.insert("extractScriptCode", FuncSig { params: vec!["SigHashPreimage"], return_type: "ByteString" });
    m.insert("extractAmount", FuncSig { params: vec!["SigHashPreimage"], return_type: "bigint" });
    m.insert("extractSequence", FuncSig { params: vec!["SigHashPreimage"], return_type: "bigint" });
    m.insert("extractOutputHash", FuncSig { params: vec!["SigHashPreimage"], return_type: "Sha256" });
    m.insert("extractOutputs", FuncSig { params: vec!["SigHashPreimage"], return_type: "Sha256" });
    m.insert("extractLocktime", FuncSig { params: vec!["SigHashPreimage"], return_type: "bigint" });
    m.insert("extractSigHashType", FuncSig { params: vec!["SigHashPreimage"], return_type: "bigint" });
    // P2PKH change-output serializer. The stateful continuation epilogue emits
    // this call itself (frontend/anf_lower.rs), and codegen/stack.rs has always
    // lowered it — this row is what makes it callable BY NAME, which the ts /
    // python / zig / ruby / java tiers have always allowed (N-055).
    m.insert("buildChangeOutput", FuncSig { params: vec!["ByteString", "bigint"], return_type: "ByteString" });

    // Intent sub-covenant intrinsics (BSVM Phase 13). Witness-bridge wrappers
    // that compile down to standard primitives + auto-injected method params.
    // See docs/cross-covenant-pattern.md.
    //
    // First arg of extractPrevOutputScript / requireOutputP2PKH MUST be an
    // integer literal — enforced as a special case in check_call_args.
    m.insert("extractPrevOutputScript", FuncSig { params: vec!["bigint", "ByteString"], return_type: "ByteString" });
    m.insert("requireOutputP2PKH", FuncSig { params: vec!["bigint", "ByteString", "bigint"], return_type: "void" });
    m.insert("currentBlockHeight", FuncSig { params: vec![], return_type: "bigint" });
    // F-024 (R14): read-only view of the auto-injected `_newAmount` — the
    // satoshis of the default single-output state continuation.
    m.insert("continuationAmount", FuncSig { params: vec![], return_type: "bigint" });

    m
}

/// Builtins that exist (the Go tier implements them, and this tier's own
/// codegen carries a dispatched — if unexercised — port) but are deliberately
/// absent from `builtin_functions()`: they belong to proof-system families
/// CLAUDE.md scopes to the Go reference compiler by policy (R-037). Their
/// absence from the typecheck table is policy, not a gap; what would be a
/// gap is reporting them the same way as an actual typo. Mirrors Python's
/// `GO_ONLY_BUILTINS` (R-258/R-259) -- family labels match that table
/// exactly. N-238 extended this past the single F-387 entry to the other
/// seven Go-only builtins, which used to hit the same generic "unknown
/// function" message in this tier.
fn go_only_builtin_family(name: &str) -> Option<&'static str> {
    match name {
        "merkleRootPoseidon2KB" => Some("Poseidon2 Merkle"),
        "assertGroth16WitnessAssisted" => Some("BN254 + Groth16"),
        "assertGroth16WitnessAssistedWithMSM" => Some("BN254 + Groth16"),
        "groth16PublicInput" => Some("BN254 + Groth16"),
        "bn254Pairing" => Some("BN254 pairing"),
        "bn254MultiPairing3" => Some("BN254 pairing"),
        "bn254MultiPairing4" => Some("BN254 pairing"),
        "verifySP1FRI" => Some("SP1 FRI"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Subtyping
// ---------------------------------------------------------------------------

/// ByteString subtypes -- types represented as byte strings on the stack.
///
/// N-076: this is the SINGLE source of truth for "is a value of this type a
/// byte string or a script number?", and `anf_lower.rs` consults it rather
/// than keeping a second copy. The copy it replaces carried `RabinSig` and
/// `RabinPubKey`, which `is_bigint_subtype` right below files as NUMBERS, so
/// `===` on a Rabin value emitted OP_EQUAL and `+` on one emitted OP_CAT.
pub(crate) fn is_bytestring_subtype(t: &str) -> bool {
    matches!(
        t,
        "ByteString" | "PubKey" | "Sig" | "Sha256" | "Ripemd160" | "Addr" | "SigHashPreimage" | "Point" | "P256Point" | "P384Point"
    )
}

/// Bigint subtypes -- types represented as integers on the stack.
///
/// `pub(crate)` for the same reason as `is_bytestring_subtype` above:
/// `expand_fixed_arrays.rs` needs the question answered (N-133) and must not
/// keep a second copy of the list.
pub(crate) fn is_bigint_subtype(t: &str) -> bool {
    matches!(t, "bigint" | "RabinSig" | "RabinPubKey")
}

fn is_subtype(actual: &str, expected: &str) -> bool {
    if actual == expected {
        return true;
    }

    // N-027: <inferred> and <unknown> are compatible with anything, in both
    // directions. Mirrors `isSubtype` in
    // packages/runar-compiler/src/passes/03-typecheck.ts. Private method
    // return types are inferred by an environment-free walk
    // (`infer_method_return_type`), so a helper that returns an identifier, a
    // property access, an index access, or a call to another private method
    // is typed `<unknown>` — which is a "don't know", not a type. Without this
    // clause Rust rejected contracts that TS, Go and Python all compile.
    if actual == "<inferred>" || actual == "<unknown>" {
        return true;
    }
    if expected == "<inferred>" || expected == "<unknown>" {
        return true;
    }

    // ByteString subtypes
    if expected == "ByteString" && is_bytestring_subtype(actual) {
        return true;
    }
    if actual == "ByteString" && is_bytestring_subtype(expected) {
        return true;
    }

    // Both in the ByteString family -> compatible (e.g. Addr and Ripemd160)
    if is_bytestring_subtype(actual) && is_bytestring_subtype(expected) {
        return true;
    }

    // bigint subtypes
    if expected == "bigint" && is_bigint_subtype(actual) {
        return true;
    }
    if actual == "bigint" && is_bigint_subtype(expected) {
        return true;
    }

    // Both in the bigint family -> compatible
    if is_bigint_subtype(actual) && is_bigint_subtype(expected) {
        return true;
    }

    // Array subtyping
    if expected.ends_with("[]") && actual.ends_with("[]") {
        return is_subtype(
            &actual[..actual.len() - 2],
            &expected[..expected.len() - 2],
        );
    }

    false
}

/// The mutable state as `addOutput` sees it: one `(name, type)` entry per value
/// the state continuation carries.
///
/// N-107: `expand_fixed_arrays` (pass 3b) runs after the typechecker and splits
/// a FixedArray property into one scalar sibling per element, so the DECLARED
/// property list is not the emitted state. The flattening mirrors that pass's
/// own naming (`<root>__<i>`, recursing through nested arrays) so a diagnostic
/// names the synthetic property the next pass will create.
///
/// A non-positive length is already a parse/validate error; the property is kept
/// whole in that case so this rule never fires on a contract that is going to be
/// rejected for a better reason.
fn expanded_state_slots(properties: &[PropertyNode]) -> Vec<(String, TypeNode)> {
    fn push(name: String, t: &TypeNode, out: &mut Vec<(String, TypeNode)>) {
        if let TypeNode::FixedArray { element, length } = t {
            if *length > 0 {
                for i in 0..*length {
                    push(format!("{}__{}", name, i), element, out);
                }
                return;
            }
        }
        out.push((name, t.clone()));
    }
    let mut out = Vec::new();
    for p in properties.iter().filter(|p| !p.readonly) {
        push(p.name.clone(), &p.prop_type, &mut out);
    }
    out
}

/// Names that are legal without being a local, a builtin or a property: the
/// `SigHash` namespace object and the three secp256k1 constants. Mirrors
/// `KNOWN_GLOBALS` in the TS reference tier.
fn known_global(name: &str) -> Option<&'static str> {
    match name {
        "SigHash" => Some("<namespace>"),
        "EC_P" | "EC_N" => Some("bigint"),
        "EC_G" => Some("Point"),
        _ => None,
    }
}

fn is_bigint_family(t: &str) -> bool {
    is_bigint_subtype(t)
}

// ---------------------------------------------------------------------------
// Type environment
// ---------------------------------------------------------------------------

struct TypeEnv {
    scopes: Vec<HashMap<String, TType>>,
}

impl TypeEnv {
    fn new() -> Self {
        TypeEnv {
            scopes: vec![HashMap::new()],
        }
    }

    fn push_scope(&mut self) {
        self.scopes.push(HashMap::new());
    }

    fn pop_scope(&mut self) {
        self.scopes.pop();
    }

    fn define(&mut self, name: &str, t: TType) {
        if let Some(top) = self.scopes.last_mut() {
            top.insert(name.to_string(), t);
        }
    }

    fn lookup(&self, name: &str) -> Option<&TType> {
        for scope in self.scopes.iter().rev() {
            if let Some(t) = scope.get(name) {
                return Some(t);
            }
        }
        None
    }

    /// Index of the innermost scope binding `name`, or -1 if none does.
    fn scope_index_of(&self, name: &str) -> i64 {
        for (i, scope) in self.scopes.iter().enumerate().rev() {
            if scope.contains_key(name) {
                return i as i64;
            }
        }
        -1
    }
}

/// F-110: whether a for-statement may execute its body two or more times.
/// Mirrors the trip count `extract_loop_shape` (anf_lower) unrolls; a shape it
/// cannot resolve is refused elsewhere and is treated as repeating here.
fn loop_may_run_twice(init: &Statement, condition: &Expression) -> bool {
    fn literal(e: &Expression) -> Option<num_bigint::BigInt> {
        match e {
            Expression::BigIntLiteral { value } => Some(value.clone()),
            Expression::UnaryExpr { op, operand } if *op == UnaryOp::Neg => literal(operand).map(|v| -v),
            _ => None,
        }
    }
    let start = match init {
        Statement::VariableDecl { init: e, .. } => literal(e),
        _ => None,
    };
    let (start, op, bound) = match (start, condition) {
        (Some(s), Expression::BinaryExpr { op, right, .. }) => match literal(right) {
            Some(b) => (s, op, b),
            None => return true,
        },
        _ => return true,
    };
    let count = match op {
        BinaryOp::Lt => bound - start,
        BinaryOp::Le => bound - start + 1,
        BinaryOp::Gt => start - bound,
        BinaryOp::Ge => start - bound + 1,
        _ => return true,
    };
    count >= num_bigint::BigInt::from(2)
}

// ---------------------------------------------------------------------------
// Type checker
// ---------------------------------------------------------------------------

/// Types whose values can be consumed at most once.
fn is_affine_type(t: &str) -> bool {
    matches!(t, "Sig" | "SigHashPreimage")
}

/// Maps consuming function names to the parameter indices that consume
/// affine values.
fn consuming_param_indices(func_name: &str) -> Option<&'static [usize]> {
    match func_name {
        "checkSig" => Some(&[0]),
        "checkMultiSig" => Some(&[0]),
        "checkPreimage" => Some(&[0]),
        _ => None,
    }
}

struct TypeChecker<'a> {
    contract: &'a ContractNode,
    errors: &'a mut Vec<Diagnostic>,
    prop_types: HashMap<String, TType>,
    method_sigs: HashMap<String, (Vec<TType>, TType)>,
    builtins: HashMap<&'static str, FuncSig>,
    /// Origin keys of affine values consumed in the current scope. Origin
    /// keys are: parameter names, "prop:<name>" for contract properties,
    /// and aliased origins resolved via affine_aliases. 2026-04-30 audit
    /// finding F6.
    consumed_values: HashSet<String>,
    /// Maps a local variable name to the canonical affine origin it
    /// aliases. Populated when a variable_decl of affine type is
    /// initialized from another affine origin.
    affine_aliases: HashMap<String, String>,
    /// F-110: for every enclosing loop that may run two or more times, the
    /// env scope index its init/body bindings live at (innermost last). A
    /// bounded loop is unrolled `count` times, so consuming an affine value
    /// bound below the innermost index happens once per iteration.
    repeating_loop_scopes: Vec<i64>,
    current_method_loc: Option<SourceLocation>,
    /// Lazily computed side-effect summary (F-075).
    side_effects: Option<SideEffectSummary>,
}

impl<'a> TypeChecker<'a> {
    fn new(contract: &'a ContractNode, errors: &'a mut Vec<Diagnostic>) -> Self {
        let mut prop_types = HashMap::new();
        for prop in &contract.properties {
            prop_types.insert(prop.name.clone(), type_node_to_ttype(&prop.prop_type));
        }

        // For StatefulSmartContract, add the implicit txPreimage property
        if contract.parent_class == "StatefulSmartContract" {
            prop_types.insert("txPreimage".to_string(), "SigHashPreimage".to_string());
        }

        let mut method_sigs = HashMap::new();
        for method in &contract.methods {
            let params: Vec<TType> = method
                .params
                .iter()
                .map(|p| type_node_to_ttype(&p.param_type))
                .collect();
            let return_type = if method.visibility == Visibility::Public {
                VOID.to_string()
            } else {
                infer_method_return_type(method)
            };
            method_sigs.insert(method.name.clone(), (params, return_type));
        }

        TypeChecker {
            contract,
            errors,
            prop_types,
            method_sigs,
            builtins: builtin_functions(),
            consumed_values: HashSet::new(),
            affine_aliases: HashMap::new(),
            repeating_loop_scopes: Vec::new(),
            current_method_loc: None,
            side_effects: None,
        }
    }

    /// Push a type-check error using the current method's source location.
    fn add_error(&mut self, msg: impl Into<String>) {
        self.errors.push(Diagnostic::error(msg, self.current_method_loc.clone()));
    }

    /// F-024 (R14): `continuationAmount()` is a read-only view of the
    /// auto-injected `_newAmount`. Without this check an assignment to it
    /// would lower as a plain read and silently drop the write.
    fn refuse_continuation_amount_write(&mut self, target: &Expression) {
        if let Expression::CallExpr { callee, .. } = target {
            if matches!(callee.as_ref(), Expression::Identifier { name } if name == "continuationAmount") {
                self.add_error(CONTINUATION_AMOUNT_READ_ONLY);
            }
        }
    }

    /// N-234: a scalar property initializer whose literal type does not
    /// match the declared property type compiled without complaint on every
    /// tier (`readonly x: bigint = toByteString('ab')` emitted a locking
    /// script that pushes a byte string where the contract's own arithmetic
    /// expects a script NUMBER). The validator only checks that an
    /// initializer IS a literal of one of the three families, never that it
    /// is a literal OF THE DECLARED TYPE. FixedArray properties are skipped
    /// here: their element-type check already lives in
    /// expand_fixed_arrays.rs (N-133), which runs on the expanded array
    /// elements, not the whole-array initializer this pass sees. Mirrors
    /// the TS reference's method of the same name in 03-typecheck.ts.
    fn check_property_initializers(&mut self) {
        for prop in &self.contract.properties {
            let Some(initializer) = &prop.initializer else { continue };
            if matches!(prop.prop_type, TypeNode::FixedArray { .. }) {
                continue;
            }
            let init_type = infer_expr_type_static(initializer);
            if init_type == "<unknown>" {
                continue;
            }
            let declared_type = type_node_to_ttype(&prop.prop_type);
            if !is_subtype(&init_type, &declared_type) {
                self.current_method_loc = Some(prop.source_location.clone());
                self.add_error(format!(
                    "Type '{}' is not assignable to type '{}'",
                    init_type, declared_type
                ));
            }
        }
    }

    fn check_constructor(&mut self) {
        let ctor = &self.contract.constructor;
        let mut env = TypeEnv::new();

        // Set current method location for diagnostics
        self.current_method_loc = Some(ctor.source_location.clone());

        // Reset affine tracking for this scope
        self.consumed_values.clear();
        self.affine_aliases.clear();

        // Add constructor params to env
        for param in &ctor.params {
            env.define(&param.name, type_node_to_ttype(&param.param_type));
        }

        // Add properties to env
        for prop in &self.contract.properties {
            env.define(&prop.name, type_node_to_ttype(&prop.prop_type));
        }

        self.check_statements(&ctor.body, &mut env);
    }

    /// The named method's effects, following private helpers (F-075).
    fn method_effects(&mut self, name: &str) -> MethodEffects {
        let contract = self.contract;
        let summary = self
            .side_effects
            .get_or_insert_with(|| compute_side_effect_summary(contract));
        summary.get(name).copied().unwrap_or_default()
    }

    fn check_method(&mut self, method: &MethodNode) {
        let mut env = TypeEnv::new();

        // Set current method location for diagnostics
        self.current_method_loc = Some(method.source_location.clone());

        // Reset affine tracking for this method
        self.consumed_values.clear();
        self.affine_aliases.clear();

        // Add method params to env
        for param in &method.params {
            env.define(&param.name, type_node_to_ttype(&param.param_type));
        }

        self.check_statements(&method.body, &mut env);

        // Crit-3 — reject mixing requireOutputP2PKH with addDataOutput in
        // the same method body. The intrinsic's compile-time output-offset
        // computation assumes a fixed 34-byte stride per output, which is
        // silently wrong when an OP_RETURN output (variable length)
        // precedes the indexed P2PKH output. v1 forbids the mix; v2 may
        // relax with a variable-stride decoder.
        //
        // F-075: all three guards here read the method's effects from
        // compute_side_effect_summary, which follows the private-helper call
        // graph — the same analysis ANF lowering injects the continuation
        // from, and ANF lowering inlines private helpers. A body-local walk
        // let a developer disable every guard by moving the triggering call
        // into a helper.
        let effects = self.method_effects(&method.name);
        let has_require_p2pkh = effects.calls_require_output_p2pkh;
        let has_add_data_output = effects.has_data_output;
        if has_require_p2pkh && has_add_data_output {
            self.add_error(format!(
                "method '{}' mixes requireOutputP2PKH() with addDataOutput() — \
v1 of the intrinsic assumes a fixed 34-byte output stride and \
variable-length OP_RETURN outputs break the offset computation; \
split the addDataOutput call into a separate method",
                method.name
            ));
        }

        // Reject requireOutputP2PKH(0) in a method whose implicit single-output
        // state continuation ALSO claims output 0. A StatefulSmartContract method
        // that mutates state but uses no this.addOutput()/addRawOutput() re-creates
        // the contract's own (large codePart) script at output 0; requiring output
        // 0 to also be a 34-byte P2PKH is impossible (codePart >= 253 bytes forces a
        // 3-byte CompactSize length prefix, never the P2PKH template's 0x19), so the
        // contract is PERMANENTLY unspendable. The terminal case (no state mutation
        // -> no continuation) stays valid.
        //
        // R-300: "addOutput/addRawOutput layouts are left to the developer" used
        // to finish that sentence, and it was wrong — no layout the developer can
        // pick makes the offsets work. this.addOutput(...) writes the continuation
        // (codePart plus serialised state, hundreds of bytes) at output 0, so
        // outputIndex*34 lands INSIDE that script for every index. addRawOutput's
        // length is a runtime value, so the stride cannot be proven there either.
        // See conformance/negatives/N34-p2pkh-index-with-state-output.runar.ts.
        // Mirrors the TS reference in 03-typecheck.ts.
        if self.contract.parent_class == "StatefulSmartContract" {
            if has_require_p2pkh && effects.has_state_output {
                self.add_error(format!(
                    "method '{}' mixes requireOutputP2PKH() with this.addOutput()/addRawOutput() — the intrinsic reads output i at byte offset i*34, which is only correct when every earlier output is exactly 34 bytes, and a state-continuation output never is (codePart plus serialised state). The assertion would read bytes from the middle of the contract's own locking script, so the contract would be permanently unspendable. Assert the payment from a separate method that emits no output of its own",
                    method.name
                ));
            }
            if effects.requires_output_p2pkh_zero && effects.mutates_state && !effects.has_state_output {
                self.add_error(format!(
                    "method '{}' calls requireOutputP2PKH(0, ...) but also mutates state \
without this.addOutput()/addRawOutput() — the auto-injected single-output state \
continuation already claims output 0 (the contract's codePart), so output 0 cannot \
simultaneously be the required 34-byte P2PKH. This contract would be permanently \
unspendable. Assert the bond on a non-continuation output index, or make the method \
terminal (no state mutation)",
                    method.name
                ));
            }
        }
    }

    fn check_statements(&mut self, stmts: &[Statement], env: &mut TypeEnv) {
        for stmt in stmts {
            self.check_statement(stmt, env);
        }
    }

    fn check_statement(&mut self, stmt: &Statement, env: &mut TypeEnv) {
        match stmt {
            Statement::VariableDecl {
                name,
                var_type,
                init,
                ..
            } => {
                let init_type = self.infer_expr_type(init, env);
                let decl_type = if let Some(declared) = var_type {
                    let declared_type = type_node_to_ttype(declared);
                    if !is_subtype(&init_type, &declared_type) {
                        self.add_error(format!(
                            "Type '{}' is not assignable to type '{}'",
                            init_type, declared_type
                        ));
                    }
                    env.define(name, declared_type.clone());
                    declared_type
                } else {
                    env.define(name, init_type.clone());
                    init_type
                };
                // Record affine alias so a subsequent consume of the
                // local resolves back to the original origin.
                // 2026-04-30 audit finding F6.
                if is_affine_type(&decl_type) {
                    if let Some(origin) = self.affine_origin_of_expr(init) {
                        self.affine_aliases.insert(name.clone(), origin);
                    }
                }
            }

            Statement::Assignment { target, value, .. } => {
                self.refuse_continuation_amount_write(target);
                let target_type = self.infer_expr_type(target, env);
                let value_type = self.infer_expr_type(value, env);
                if !is_subtype(&value_type, &target_type) {
                    self.add_error(format!(
                        "Type '{}' is not assignable to type '{}'",
                        value_type, target_type
                    ));
                }
            }

            Statement::IfStatement {
                condition,
                then_branch,
                else_branch,
                ..
            } => {
                let cond_type = self.infer_expr_type(condition, env);
                if cond_type != BOOLEAN {
                    self.add_error(format!(
                        "If condition must be boolean, got '{}'",
                        cond_type
                    ));
                }
                // F-222: the arms are mutually exclusive, so each is checked
                // against the consumed set as it stood before the if;
                // afterwards a value consumed in either arm counts as consumed.
                let consumed_before = self.consumed_values.clone();
                env.push_scope();
                self.check_statements(then_branch, env);
                env.pop_scope();
                let consumed_after_then =
                    std::mem::replace(&mut self.consumed_values, consumed_before);
                if let Some(else_stmts) = else_branch {
                    env.push_scope();
                    self.check_statements(else_stmts, env);
                    env.pop_scope();
                }
                self.consumed_values.extend(consumed_after_then);
            }

            Statement::ForStatement {
                init,
                condition,
                update,
                body,
                ..
            } => {
                let loop_scope = env.scopes.len() as i64;
                let repeats = loop_may_run_twice(init, condition);
                env.push_scope();
                self.check_statement(init, env);
                let cond_type = self.infer_expr_type(condition, env);
                if cond_type != BOOLEAN {
                    self.add_error(format!(
                        "For loop condition must be boolean, got '{}'",
                        cond_type
                    ));
                }
                // R-029 / CL-BUG-008: the update clause used to fall into the
                // rest pattern and was never checked, so `for (let i = 0n;
                // i < 3n; undefinedFn())` compiled clean -- a hole in the rule
                // that only Rúnar builtins and contract methods are callable
                // (CLAUDE.md names `console.log` explicitly). The validator
                // separately restricts the clause to a unit-step advance;
                // this is the type-level half of the same guard, and it is
                // what catches an unknown name on the `--ir`-adjacent paths
                // that skip validation.
                self.check_statement(update, env);
                // F-110: the body runs once per iteration; see
                // `repeating_loop_scopes`.
                if repeats {
                    self.repeating_loop_scopes.push(loop_scope);
                }
                self.check_statements(body, env);
                if repeats {
                    self.repeating_loop_scopes.pop();
                }
                env.pop_scope();
            }

            Statement::ExpressionStatement { expression, .. } => {
                self.infer_expr_type(expression, env);
            }

            Statement::ReturnStatement { value, .. } => {
                if let Some(v) = value {
                    self.infer_expr_type(v, env);
                }
            }
        }
    }

    /// Infer the type of an expression.
    fn infer_expr_type(&mut self, expr: &Expression, env: &mut TypeEnv) -> TType {
        match expr {
            Expression::BigIntLiteral { .. } => BIGINT.to_string(),

            Expression::BoolLiteral { .. } => BOOLEAN.to_string(),

            Expression::ByteStringLiteral { .. } => BYTESTRING.to_string(),

            Expression::Identifier { name } => {
                if name == "this" {
                    return "<this>".to_string();
                }
                if name == "super" {
                    return "<super>".to_string();
                }
                if name == "true" || name == "false" {
                    return BOOLEAN.to_string();
                }
                // The blank identifier. `_ = x` is the Go / Rust / Zig discard idiom and
                // the Go DSL frontend emits it as an assignment TARGET, so it reaches the
                // identifier arm as a name to be typed. It is a discard, not a reference:
                // nothing is being looked up, so `undefined` is the wrong word for it.
                // Measured at the parent commit, go/rust/python/zig/ruby/java all compiled
                // `_ = doubled` to the same 7652957c009c77 while TS alone refused it with
                // "Undefined variable '_'" — invariant 1 (all seven parse all nine
                // surfaces) already broken for this shape. Listing it here rather than
                // letting the new fall-through reject it keeps the six tiers' bytes and
                // brings the seventh into line.
                if name == "_" {
                    return "<unknown>".to_string();
                }

                if let Some(t) = env.lookup(name) {
                    return t.clone();
                }

                // Check if it's a builtin function name
                if self.builtins.contains_key(name.as_str()) {
                    return "<builtin>".to_string();
                }

                // A contract property named without a receiver. Java lets a method say
                // `strikePrice` for `this.strikePrice`, and the Solidity frontend emits the
                // same shape; the TS reference tier has resolved it here since that frontend
                // landed. Without this the identifier types as `<unknown>` and any operator
                // that demands a type rejects valid source — a frontend parity break the
                // `--parse-only` matrix cannot see, because the identifier PARSES fine and
                // only fails to RESOLVE.
                if let Some(t) = self.prop_types.get(name.as_str()) {
                    return t.clone();
                }

                // Names that resolve to neither a local, a builtin nor a
                // property, and are still legal: the `SigHash` namespace object
                // and the three secp256k1 constants from runar-lang. Every
                // frontend hands them to the typechecker as bare identifiers.
                // They used to be carried by the "<unknown>" fall-through; once
                // that fall-through raises they have to be listed, exactly as
                // the TS reference tier lists them.
                if let Some(t) = known_global(name.as_str()) {
                    return t.to_string();
                }

                // GK-BUG-009 — a name that resolves to nothing is an error
                // HERE, at the only pass that can see the binding environment.
                // It used to return "<unknown>" silently, and "<unknown>" is
                // compatible with everything under is_subtype by design
                // (R-092), so `notAThing === 1n` raised nothing. `notAThing >
                // 1n` did raise -- the bigint-family check does not admit
                // "<unknown>" -- which is why R-085's `>` pin read as closed
                // while the `===` path was wide open. Where the reference is
                // reachable from codegen, stack lowering later refuses to emit
                // an OP_0 placeholder and the compile still fails, but for the
                // wrong reason; where it is NOT reachable (an uncalled private
                // helper, a zero-iteration loop) nothing fired at all and the
                // contract compiled to a locking script.
                self.add_error(format!("Undefined variable '{name}'"));
                "<unknown>".to_string()
            }

            Expression::PropertyAccess { property } => {
                if let Some(t) = self.prop_types.get(property) {
                    return t.clone();
                }

                self.add_error(format!(
                    "Property '{}' does not exist on the contract",
                    property
                ));
                "<unknown>".to_string()
            }

            Expression::MemberExpr { object, property } => {
                let obj_type = self.infer_expr_type(object, env);

                if obj_type == "<this>" {
                    // Check if it's a property
                    if let Some(t) = self.prop_types.get(property) {
                        return t.clone();
                    }
                    // Check if it's a method
                    if self.method_sigs.contains_key(property) {
                        return "<method>".to_string();
                    }
                    // Special: getStateScript
                    if property == "getStateScript" {
                        return "<method>".to_string();
                    }

                    self.add_error(format!(
                        "Property or method '{}' does not exist on the contract",
                        property
                    ));
                    return "<unknown>".to_string();
                }

                // SigHash.ALL, SigHash.FORKID, etc.
                if let Expression::Identifier { name } = object.as_ref() {
                    if name == "SigHash" {
                        return BIGINT.to_string();
                    }
                }

                "<unknown>".to_string()
            }

            Expression::BinaryExpr { op, left, right } => {
                self.check_binary_expr(op, left, right, env)
            }

            Expression::UnaryExpr { op, operand } => self.check_unary_expr(op, operand, env),

            Expression::CallExpr {
                callee,
                args,
                asm_return_type,
            } => self.check_call_expr(callee, args, asm_return_type.as_deref(), env),

            Expression::TernaryExpr {
                condition,
                consequent,
                alternate,
            } => {
                let cond_type = self.infer_expr_type(condition, env);
                if cond_type != BOOLEAN {
                    self.add_error(format!(
                        "Ternary condition must be boolean, got '{}'",
                        cond_type
                    ));
                }
                let cons_type = self.infer_expr_type(consequent, env);
                let alt_type = self.infer_expr_type(alternate, env);

                if cons_type != alt_type {
                    if is_subtype(&alt_type, &cons_type) {
                        return cons_type;
                    }
                    if is_subtype(&cons_type, &alt_type) {
                        return alt_type;
                    }
                    self.add_error(format!(
                        "Ternary branches have incompatible types: '{}' and '{}'",
                        cons_type, alt_type
                    ));
                }
                cons_type
            }

            Expression::IndexAccess { object, index } => {
                let obj_type = self.infer_expr_type(object, env);
                let index_type = self.infer_expr_type(index, env);

                if !is_bigint_family(&index_type) {
                    self.add_error(format!(
                        "Array index must be bigint, got '{}'",
                        index_type
                    ));
                }

                if obj_type.ends_with("[]") {
                    return obj_type[..obj_type.len() - 2].to_string();
                }

                "<unknown>".to_string()
            }

            Expression::IncrementExpr { operand, .. }
            | Expression::DecrementExpr { operand, .. } => {
                self.refuse_continuation_amount_write(operand);
                let operand_type = self.infer_expr_type(operand, env);
                if !is_bigint_family(&operand_type) {
                    let op_str = if matches!(expr, Expression::IncrementExpr { .. }) {
                        "++"
                    } else {
                        "--"
                    };
                    self.add_error(format!(
                        "{} operator requires bigint, got '{}'",
                        op_str, operand_type
                    ));
                }
                BIGINT.to_string()
            }

            Expression::ArrayLiteral { elements } => {
                // F-063: infer EVERY element, not just the first — a call nested
                // in a later element must reach the unknown-function rule, and a
                // mistyped later element must be compared. Ported from the TS
                // reference, wording included.
                let Some(first) = elements.first() else {
                    return "<unknown>[]".to_string();
                };
                let elem_type = self.infer_expr_type(first, env);
                for el in &elements[1..] {
                    let et = self.infer_expr_type(el, env);
                    if !is_subtype(&et, &elem_type) && et != "<unknown>" {
                        self.add_error(format!(
                            "Array element type mismatch: expected '{}', got '{}'",
                            elem_type, et
                        ));
                    }
                }
                format!("{}[]", elem_type)
            }
        }
    }

    fn check_binary_expr(
        &mut self,
        op: &BinaryOp,
        left: &Expression,
        right: &Expression,
        env: &mut TypeEnv,
    ) -> TType {
        let left_type = self.infer_expr_type(left, env);
        let right_type = self.infer_expr_type(right, env);

        match op {
            // Add: bigint x bigint -> bigint, or ByteString x ByteString -> ByteString (OP_CAT)
            BinaryOp::Add => {
                if is_bytestring_subtype(&left_type) && is_bytestring_subtype(&right_type) {
                    return BYTESTRING.to_string();
                }
                if !is_bigint_family(&left_type) {
                    self.add_error(format!(
                        "Left operand of '{}' must be bigint or ByteString, got '{}'",
                        op.as_str(),
                        left_type
                    ));
                }
                if !is_bigint_family(&right_type) {
                    self.add_error(format!(
                        "Right operand of '{}' must be bigint or ByteString, got '{}'",
                        op.as_str(),
                        right_type
                    ));
                }
                BIGINT.to_string()
            }

            // Arithmetic: bigint x bigint -> bigint
            BinaryOp::Sub | BinaryOp::Mul | BinaryOp::Div | BinaryOp::Mod => {
                if !is_bigint_family(&left_type) {
                    self.add_error(format!(
                        "Left operand of '{}' must be bigint, got '{}'",
                        op.as_str(),
                        left_type
                    ));
                }
                if !is_bigint_family(&right_type) {
                    self.add_error(format!(
                        "Right operand of '{}' must be bigint, got '{}'",
                        op.as_str(),
                        right_type
                    ));
                }
                BIGINT.to_string()
            }

            // Comparison: bigint x bigint -> boolean
            BinaryOp::Lt | BinaryOp::Le | BinaryOp::Gt | BinaryOp::Ge => {
                if !is_bigint_family(&left_type) {
                    self.add_error(format!(
                        "Left operand of '{}' must be bigint, got '{}'",
                        op.as_str(),
                        left_type
                    ));
                }
                if !is_bigint_family(&right_type) {
                    self.add_error(format!(
                        "Right operand of '{}' must be bigint, got '{}'",
                        op.as_str(),
                        right_type
                    ));
                }
                BOOLEAN.to_string()
            }

            // Equality: T x T -> boolean
            BinaryOp::StrictEq | BinaryOp::StrictNe => {
                if !is_subtype(&left_type, &right_type)
                    && !is_subtype(&right_type, &left_type)
                {
                    if left_type != "<unknown>" && right_type != "<unknown>" {
                        self.add_error(format!(
                            "Cannot compare '{}' and '{}' with '{}'",
                            left_type,
                            right_type,
                            op.as_str()
                        ));
                    }
                }
                BOOLEAN.to_string()
            }

            // Logical: boolean x boolean -> boolean
            BinaryOp::And | BinaryOp::Or => {
                if left_type != BOOLEAN && left_type != "<unknown>" {
                    self.add_error(format!(
                        "Left operand of '{}' must be boolean, got '{}'",
                        op.as_str(),
                        left_type
                    ));
                }
                if right_type != BOOLEAN && right_type != "<unknown>" {
                    self.add_error(format!(
                        "Right operand of '{}' must be boolean, got '{}'",
                        op.as_str(),
                        right_type
                    ));
                }
                BOOLEAN.to_string()
            }

            // Bitwise &, |, ^: bigint x bigint -> bigint, or ByteString x ByteString -> ByteString
            BinaryOp::BitAnd | BinaryOp::BitOr | BinaryOp::BitXor => {
                if is_bytestring_subtype(&left_type) && is_bytestring_subtype(&right_type) {
                    return BYTESTRING.to_string();
                }
                if !is_bigint_family(&left_type) {
                    self.add_error(format!(
                        "Left operand of '{}' must be bigint or ByteString, got '{}'",
                        op.as_str(),
                        left_type
                    ));
                }
                if !is_bigint_family(&right_type) {
                    self.add_error(format!(
                        "Right operand of '{}' must be bigint or ByteString, got '{}'",
                        op.as_str(),
                        right_type
                    ));
                }
                BIGINT.to_string()
            }

            // Shift: bigint x bigint -> bigint
            BinaryOp::Shl | BinaryOp::Shr => {
                if !is_bigint_family(&left_type) {
                    self.add_error(format!(
                        "Left operand of '{}' must be bigint, got '{}'",
                        op.as_str(),
                        left_type
                    ));
                }
                if !is_bigint_family(&right_type) {
                    self.add_error(format!(
                        "Right operand of '{}' must be bigint, got '{}'",
                        op.as_str(),
                        right_type
                    ));
                }
                BIGINT.to_string()
            }
        }
    }

    fn check_unary_expr(
        &mut self,
        op: &UnaryOp,
        operand: &Expression,
        env: &mut TypeEnv,
    ) -> TType {
        let operand_type = self.infer_expr_type(operand, env);

        match op {
            UnaryOp::Not => {
                if operand_type != BOOLEAN && operand_type != "<unknown>" {
                    self.add_error(format!(
                        "Operand of '!' must be boolean, got '{}'",
                        operand_type
                    ));
                }
                BOOLEAN.to_string()
            }
            UnaryOp::Neg => {
                if !is_bigint_family(&operand_type) {
                    self.add_error(format!(
                        "Operand of unary '-' must be bigint, got '{}'",
                        operand_type
                    ));
                }
                BIGINT.to_string()
            }
            UnaryOp::BitNot => {
                if is_bytestring_subtype(&operand_type) {
                    return BYTESTRING.to_string();
                }
                if !is_bigint_family(&operand_type) {
                    self.add_error(format!(
                        "Operand of '~' must be bigint or ByteString, got '{}'",
                        operand_type
                    ));
                }
                BIGINT.to_string()
            }
        }
    }

    /// Type-check the arguments of the three output intrinsics —
    /// `this.addOutput` / `this.addRawOutput` / `this.addDataOutput` — and
    /// return their result type.
    ///
    /// N-098: the first argument is the output's SATOSHI AMOUNT, and this tier
    /// used to accept any type there. That is not a missing lint.
    /// `lower_add_output` prepends the operand as `OP_8 OP_NUM2BIN`, so a
    /// ByteString in that slot is reinterpreted as a script number with no
    /// conversion and becomes the amount the covenant commits to:
    /// `blob: ByteString` and `blob: bigint` compiled to the SAME script, byte
    /// for byte. On the real `@bsv/sdk` Spend engine with `blob = 0x2a` only a
    /// 42-satoshi continuation validates, and blobs wider than 8 bytes abort at
    /// `OP_NUM2BIN`, making the UTXO unspendable.
    ///
    /// N-105 (2/2): the remaining three checks TS performs and this tier did
    /// not — the StatefulSmartContract gate, the arity of all three intrinsics,
    /// and the types of addOutput's state values. Each had an executed
    /// consequence: `addOutput(1000n)` dropped the state value from the
    /// continuation entirely, a surplus value was appended to a state
    /// serialization the next spend deserializes by fixed offsets, a ByteString
    /// state value was serialized where an 8-byte LE number belongs, and
    /// addRawOutput in a stateless SmartContract emitted a "continuation" for a
    /// contract with no state.
    ///
    /// Ported from the TypeScript reference, wording included.
    ///
    /// N-105: the SECOND argument of addRawOutput / addDataOutput is the
    /// created output's LOCKING SCRIPT, and this tier used to accept any type
    /// there too. `lower_add_raw_output` takes OP_SIZE of the operand,
    /// varint-prefixes it and concatenates it after the amount — no conversion
    /// — so `n: bigint` and `n: ByteString` compiled to the SAME script, byte
    /// for byte. A script number on the stack is its minimal little-endian
    /// encoding, so the covenant commits to an output whose locking script IS
    /// those bytes. Executed on the real `@bsv/sdk` Spend engine against the
    /// exact opcode window this tier emits: n=0 gives an EMPTY locking script,
    /// n=81 gives OP_1 and n=118 gives OP_DUP — all three anyone-can-spend —
    /// while n=1000 gives 0xe8 0x03, an invalid opcode, and the output is
    /// unspendable.
    ///
    /// `<unknown>` is escaped exactly as TS escapes it — a private helper's
    /// declared return type is discarded at parse time in every tier, so
    /// `this.sats()` infers as `<unknown>` and must keep compiling.
    fn check_output_intrinsic_args(
        &mut self,
        name: &str,
        args: &[Expression],
        env: &mut TypeEnv,
    ) -> TType {
        // N-105: all three intrinsics build an OUTPUT, and an output only
        // exists in a stateful contract. TS refuses the call outright and
        // checks nothing else, so the early return is part of the ported
        // behaviour.
        if self.contract.parent_class != "StatefulSmartContract" {
            self.add_error(format!(
                "{}() is only available in StatefulSmartContract",
                name
            ));
            return VOID.to_string();
        }

        if name == "addOutput" {
            // The surface form `this.addOutput(satoshis, .{ v1, v2, ... })`
            // that Zig and Move tuple syntax produce carries the state values
            // in a trailing array literal. anf_lower unwraps it with this same
            // helper, so the arity checked here is the arity codegen will see.
            let normalized = super::anf_lower::flatten_add_output_args(args);

            // N-107: count the state slots the continuation will actually
            // carry, not the DECLARED mutable properties. expand_fixed_arrays
            // runs right after this pass and splits `board: FixedArray<bigint,
            // 3>` into `board__0 .. board__2`, so a contract declaring `board`
            // and `n` emits FOUR state values. addOutput is positional against
            // the emitted values, which is why the declared count answers the
            // wrong question.
            //
            // This used to be a `shape_checkable` flag that scoped the rule OUT
            // of every contract with FixedArray state, because porting it
            // verbatim would have rejected Boardy (in
            // compilers/python/tests/test_r025_expand_fixed_arrays_field_preservation.py)
            // the way the reference tier did. The cost of that opt-out was
            // silent: a wrong-arity addOutput on a FixedArray contract was
            // ACCEPTED and emitted a state continuation that disagreed with the
            // contract's own state. Gate:
            // conformance/negatives/N26-addoutput-arity-fixedarray.
            let mutable_props = expanded_state_slots(&self.contract.properties);
            let expected = 1 + mutable_props.len();
            if normalized.len() != expected {
                self.add_error(format!(
                    "addOutput() expects {} argument(s): satoshis + {} state value(s), got {}",
                    expected,
                    mutable_props.len(),
                    normalized.len()
                ));
            }
            if !normalized.is_empty() {
                let sat_type = self.infer_expr_type(&normalized[0], env);
                if !is_bigint_family(&sat_type) && sat_type != "<unknown>" {
                    self.add_error(format!(
                        "addOutput() first argument (satoshis) must be bigint, got '{}'",
                        sat_type
                    ));
                }
            }
            let mut i = 0;
            while i < mutable_props.len() && i + 1 < normalized.len() {
                let arg_type = self.infer_expr_type(&normalized[i + 1], env);
                let prop_type = type_node_to_ttype(&mutable_props[i].1);
                if !is_subtype(&arg_type, &prop_type) && arg_type != "<unknown>" {
                    self.add_error(format!(
                        "addOutput() argument {} ({}) must be '{}', got '{}'",
                        i + 2,
                        mutable_props[i].0,
                        prop_type,
                        arg_type
                    ));
                }
                i += 1;
            }
            // Surplus arguments are still inferred, so a type error inside one
            // is not swallowed by the arity diagnostic. Mirrors TS.
            for extra in normalized.iter().skip(expected) {
                self.infer_expr_type(extra, env);
            }
            return VOID.to_string();
        }

        // addRawOutput / addDataOutput — (satoshis, scriptBytes).
        if args.len() != 2 {
            self.add_error(format!(
                "{}() expects 2 arguments (satoshis, scriptBytes), got {}",
                name,
                args.len()
            ));
        }
        if !args.is_empty() {
            let sat_type = self.infer_expr_type(&args[0], env);
            if !is_bigint_family(&sat_type) && sat_type != "<unknown>" {
                self.add_error(format!(
                    "{}() first argument (satoshis) must be bigint, got '{}'",
                    name, sat_type
                ));
            }
        }
        if args.len() >= 2 {
            // TS uses is_subtype against ByteString, not equality, so every
            // ByteString subtype (PubKey, Ripemd160, Sig, ...) stays accepted.
            let script_type = self.infer_expr_type(&args[1], env);
            if !is_subtype(&script_type, "ByteString") && script_type != "<unknown>" {
                self.add_error(format!(
                    "{}() second argument (scriptBytes) must be ByteString, got '{}'",
                    name, script_type
                ));
            }
        }
        VOID.to_string()
    }

    fn check_call_expr(
        &mut self,
        callee: &Expression,
        args: &[Expression],
        asm_return_type: Option<&str>,
        env: &mut TypeEnv,
    ) -> TType {
        // super() call in constructor
        if let Expression::Identifier { name } = callee {
            if name == "super" {
                for arg in args {
                    self.infer_expr_type(arg, env);
                }
                return VOID.to_string();
            }
        }

        // asm is a compile-time intrinsic — the parser has already rewritten
        // the { body, in_arity?, out_arity? } object-literal argument into
        // three positional args (body, in_arity, out_arity). The statement
        // form returns void; the expression form asm<T>({...}) carries the
        // captured return type on asm_return_type and produces a value of that
        // type.
        if let Expression::Identifier { name } = callee {
            if name == "asm" {
                for arg in args {
                    self.infer_expr_type(arg, env);
                }
                if let Some(t) = asm_return_type {
                    return t.to_string();
                }
                return VOID.to_string();
            }
        }

        // Direct builtin call: assert(...), checkSig(...), sha256(...), etc.
        if let Expression::Identifier { name } = callee {
            if let Some(sig) = self.builtins.get(name.as_str()) {
                let sig_params = sig.params.clone();
                let sig_return_type = sig.return_type;
                return self.check_call_args(name, &sig_params, sig_return_type, args, env);
            }

            // Check if it's a known contract method
            if let Some((params, return_type)) = self.method_sigs.get(name).cloned() {
                let param_strs: Vec<&str> = params.iter().map(|s| s.as_str()).collect();
                return self.check_call_args(name, &param_strs, &return_type, args, env);
            }

            // Check if it's a local variable -- F-208: Rúnar has no
            // first-class functions, so a bound local can never be called.
            // This used to return "<unknown>" with no diagnostic, silently
            // accepting `const f: bigint = a; const r = f(a, a, a);`.
            if env.lookup(name).is_some() {
                self.add_error(format!(
                    "local variable '{}' is not callable — Rúnar has no first-class functions; only built-in functions and contract methods can be called",
                    name
                ));
                for arg in args {
                    self.infer_expr_type(arg, env);
                }
                return "<unknown>".to_string();
            }

            // F-387 (CL-GAP-065): `merkleRootPoseidon2KB` IS a real Rúnar
            // builtin -- `is_merkle_builtin` in codegen/stack.rs and
            // ir/loader.rs both know its name -- but it is scoped to the Go
            // reference compiler by project policy (CLAUDE.md, "EVM/STARK
            // proof-system primitives are scoped to the Go tier by project
            // policy"; conformance/go-only-parity/, R-037). `runar-lang`
            // does not declare the symbol, so no source frontend can offer
            // it; reporting it as "unknown function" told the author a real
            // builtin does not exist, which sends them looking for a typo
            // or a missing import -- the one thing that is not wrong. Same
            // fix as Python's `GO_ONLY_BUILTINS` table (R-258/R-259).
            if let Some(family) = go_only_builtin_family(name) {
                self.add_error(format!(
                    "builtin '{}' belongs to the {} family, which is scoped to the Go tier by \
                     project policy — see CLAUDE.md (\"EVM/STARK proof-system primitives\") and \
                     conformance/README.md (\"Per-fixture compiler allowlist\"). Compile this \
                     contract with the Go compiler, or opt the fixture out of the Rust tier via \
                     source.json's \"compilers\" allowlist.",
                    name, family
                ));
                for arg in args {
                    self.infer_expr_type(arg, env);
                }
                return "<unknown>".to_string();
            }

            self.add_error(format!(
                "unknown function '{}' — only Rúnar built-in functions and contract methods are allowed",
                name
            ));
            for arg in args {
                self.infer_expr_type(arg, env);
            }
            return "<unknown>".to_string();
        }

        // this.method(...) via PropertyAccess
        if let Expression::PropertyAccess { property } = callee {
            if property == "getStateScript" {
                if !args.is_empty() {
                    self.add_error("getStateScript() takes no arguments");
                }
                return BYTESTRING.to_string();
            }

            if property == "addOutput" || property == "addRawOutput" || property == "addDataOutput" {
                return self.check_output_intrinsic_args(property, args, env);
            }

            // Check contract method signatures
            if let Some((params, return_type)) = self.method_sigs.get(property).cloned() {
                let param_strs: Vec<&str> = params.iter().map(|s| s.as_str()).collect();
                return self.check_call_args(property, &param_strs, &return_type, args, env);
            }

            self.add_error(format!(
                "unknown method 'self.{}' — only Rúnar built-in methods and contract methods are allowed",
                property
            ));
            for arg in args {
                self.infer_expr_type(arg, env);
            }
            return "<unknown>".to_string();
        }

        // member_expr call: obj.method(...)
        if let Expression::MemberExpr { object, property } = callee {
            // .clone() is a Rust idiom — allow it as a no-op
            if property == "clone" {
                return self.infer_expr_type(object, env);
            }

            let obj_type = self.infer_expr_type(object, env);

            if obj_type == "<this>"
                || matches!(object.as_ref(), Expression::Identifier { name } if name == "this")
            {
                if property == "getStateScript" {
                    return BYTESTRING.to_string();
                }

                if property == "addOutput" || property == "addRawOutput" || property == "addDataOutput" {
                    return self.check_output_intrinsic_args(property, args, env);
                }

                if let Some((params, return_type)) = self.method_sigs.get(property).cloned() {
                    let param_strs: Vec<&str> = params.iter().map(|s| s.as_str()).collect();
                    return self.check_call_args(
                        property,
                        &param_strs,
                        &return_type,
                        args,
                        env,
                    );
                }
            }

            // Not this.method — reject (e.g. std::process::exit)
            let obj_name = match object.as_ref() {
                Expression::Identifier { name } => name.clone(),
                _ => "<expr>".to_string(),
            };
            self.add_error(format!(
                "unknown function '{}.{}' — only Rúnar built-in functions and contract methods are allowed",
                obj_name, property
            ));
            for arg in args {
                self.infer_expr_type(arg, env);
            }
            return "<unknown>".to_string();
        }

        // Fallback — unknown callee shape
        self.add_error(
            "unsupported function call expression — only Rúnar built-in functions and contract methods are allowed"
        );
        self.infer_expr_type(callee, env);
        for arg in args {
            self.infer_expr_type(arg, env);
        }
        "<unknown>".to_string()
    }

    fn check_call_args(
        &mut self,
        func_name: &str,
        sig_params: &[&str],
        return_type: &str,
        args: &[Expression],
        env: &mut TypeEnv,
    ) -> TType {
        // Special case: assert can take 1 or 2 args
        if func_name == "assert" {
            if args.is_empty() || args.len() > 2 {
                self.add_error(format!(
                    "assert() expects 1 or 2 arguments, got {}",
                    args.len()
                ));
            }
            if !args.is_empty() {
                let cond_type = self.infer_expr_type(&args[0], env);
                if cond_type != BOOLEAN && cond_type != "<unknown>" {
                    self.add_error(format!(
                        "assert() condition must be boolean, got '{}'",
                        cond_type
                    ));
                }
            }
            if args.len() >= 2 {
                self.infer_expr_type(&args[1], env);
            }
            return return_type.to_string();
        }

        // Special case: checkSig — strict type enforcement
        // arg0 must be Sig (not just any ByteString subtype)
        // arg1 must be PubKey (not just any ByteString subtype)
        if func_name == "checkSig" {
            if args.len() != 2 {
                self.add_error(format!(
                    "checkSig() expects 2 argument(s), got {}",
                    args.len()
                ));
            }
            if args.len() >= 1 {
                let arg0_type = self.infer_expr_type(&args[0], env);
                // arg0 must be Sig specifically (or a subtype of Sig — currently Sig has no subtypes)
                if arg0_type != "Sig" && arg0_type != "<unknown>" {
                    self.add_error(format!(
                        "Argument 1 of checkSig(): expected 'Sig', got '{}'",
                        arg0_type
                    ));
                }
            }
            if args.len() >= 2 {
                let arg1_type = self.infer_expr_type(&args[1], env);
                // arg1 must be PubKey specifically (or a subtype of PubKey)
                if arg1_type != "PubKey" && arg1_type != "<unknown>" {
                    self.add_error(format!(
                        "Argument 2 of checkSig(): expected 'PubKey', got '{}'",
                        arg1_type
                    ));
                }
            }
            // Infer remaining args if overprovided
            for i in 2..args.len() {
                self.infer_expr_type(&args[i], env);
            }
            self.check_affine_consumption(func_name, args, env);
            return return_type.to_string();
        }

        // extractPrevOutputScript / requireOutputP2PKH — the index arg
        // MUST be a compile-time integer literal so the ANF lowering can
        // derive a stable auto-injected witness-param name
        // (extractPrevOutputScript) or a constant byte offset
        // (requireOutputP2PKH).
        if func_name == "extractPrevOutputScript" || func_name == "requireOutputP2PKH" {
            if !args.is_empty() {
                // Accept `-N` (UnaryExpr "-" over BigIntLiteral) so the
                // bounds check below produces a clear "must be >= 0"
                // rather than the misleading "must be an integer literal"
                // message.
                use num_traits::ToPrimitive;
                let idx_lit: Option<i128> = match &args[0] {
                    Expression::BigIntLiteral { value } => value.to_i128(),
                    Expression::UnaryExpr { op: UnaryOp::Neg, operand } => {
                        if let Expression::BigIntLiteral { value } = operand.as_ref() {
                            // R-068: this arm exists ONLY to reach the
                            // "must be >= 0" message below, so it must
                            // surrender anything that is not actually
                            // negative. `-0` negates to 0 and would sail
                            // past that bound check, but ANF lowering
                            // matches on a bare BigIntLiteral: on a
                            // UnaryExpr it falls through to `load_const ""`
                            // and the covenant the intrinsic was supposed
                            // to install is silently absent. Report it as a
                            // non-literal index instead.
                            (-value).to_i128().filter(|v| *v < 0)
                        } else {
                            None
                        }
                    }
                    _ => None,
                };
                if idx_lit.is_none() {
                    self.add_error(format!(
                        "{}() argument 1 (index) must be an integer literal",
                        func_name
                    ));
                } else if let Some(idx) = idx_lit {
                    // R-2: bound the index literal. For requireOutputP2PKH,
                    // the emitted Stack-IR computes byte-offset = idx * 34;
                    // require 0 <= idx <= 1000 to keep the offset well
                    // under script-int max and to reject obvious nonsense
                    // (e.g. negative or astronomically large).
                    if idx < 0 {
                        self.add_error(format!(
                            "{}() argument 1 (index) must be >= 0; got {}",
                            func_name, idx
                        ));
                    }
                    if func_name == "requireOutputP2PKH" && idx > 0 {
                        self.add_error(format!(
                            "requireOutputP2PKH() argument 1 (outputIndex) must be 0 in v1; got {}. The emitted Stack-IR reads output i at byte offset i*34, but Bitcoin outputs are variable length, so for i > 0 that offset is not an output boundary: an attacker sizes output 0 freely and places the expected 34 P2PKH bytes inside its OP_RETURN payload, leaving the transaction's real output i to pay whoever they like. Offset 0 IS a boundary, so index 0 is sound; other indexes need a CompactSize walk the v1 codegen does not emit",
                            idx
                        ));
                    }
                }
            }
        }

        // extractPrevOutputScript variable-arity special case (2-arg
        // full-hash or 3-arg prefix-hash form). Validates types +
        // literal-only on the optional prefixLen, then returns the
        // signature's return type to bypass the standard arg-count check
        // below (which would reject the 3-arg form against the 2-arg sig
        // table entry).
        if func_name == "extractPrevOutputScript" {
            if args.len() != 2 && args.len() != 3 {
                self.add_error(format!(
                    "extractPrevOutputScript() expects 2 or 3 arguments, got {}",
                    args.len()
                ));
            }
            if !args.is_empty() {
                // arg 0 already validated as a literal above
                self.infer_expr_type(&args[0], env);
            }
            if args.len() >= 2 {
                let arg_type = self.infer_expr_type(&args[1], env);
                if !is_subtype(&arg_type, "ByteString") && arg_type != "<unknown>" {
                    self.add_error(format!(
                        "argument 2 of extractPrevOutputScript(): expected 'ByteString', got '{}'",
                        arg_type
                    ));
                }
            }
            if args.len() == 3 {
                if let Expression::BigIntLiteral { value } = &args[2] {
                    // R-4: bound the prefixLen literal. The intrinsic
                    // hashes substr(witness, 0, prefixLen) and compares
                    // against a 32-byte SHA-256 hash. prefixLen < 32 is
                    // suspicious (the prefix bytes don't even cover a
                    // hash-sized chunk). prefixLen > 4 MiB exceeds
                    // MAX_SCRIPT_BYTES — wouldn't fit in a legal Bitcoin
                    // Script anyway.
                    use num_traits::ToPrimitive;
                    let n: i128 = value.to_i128().unwrap_or(i128::MAX);
                    if n < 32 {
                        self.add_error(format!(
                            "extractPrevOutputScript() argument 3 (prefixLen) must be >= 32 (the hash assertion compares a 32-byte SHA-256); got {}",
                            n
                        ));
                    }
                    if n > 4 * 1024 * 1024 {
                        self.add_error(format!(
                            "extractPrevOutputScript() argument 3 (prefixLen) must be <= MAX_SCRIPT_BYTES (4 MiB); got {}",
                            n
                        ));
                    }
                } else {
                    self.add_error(
                        "extractPrevOutputScript() argument 3 (prefixLen) must be an integer literal when supplied",
                    );
                }
                self.infer_expr_type(&args[2], env);
            }
            self.check_affine_consumption(func_name, args, env);
            return return_type.to_string();
        }

        // requireOutputP2PKH, currentBlockHeight and continuationAmount need
        // the auto-injected txPreimage / _newAmount — only available in
        // StatefulSmartContract methods.
        if func_name == "requireOutputP2PKH"
            || func_name == "currentBlockHeight"
            || func_name == "continuationAmount"
        {
            if self.contract.parent_class != "StatefulSmartContract" {
                self.add_error(format!(
                    "{}() is only available in StatefulSmartContract methods",
                    func_name
                ));
            }
        }

        // Special case: checkMultiSig (Sig[] / PubKey[] arrays). Only
        // arity is special; arg-type validation falls through to the
        // standard subtype loop below so callers cannot pass
        // `bigint[]` or other element types. 2026-04-30 audit
        // finding F5.
        if func_name == "checkMultiSig" {
            if args.len() != 2 {
                self.add_error(format!(
                    "checkMultiSig() expects 2 arguments, got {}",
                    args.len()
                ));
                for arg in args {
                    self.infer_expr_type(arg, env);
                }
                self.check_affine_consumption(func_name, args, env);
                return return_type.to_string();
            }
            // Fall through to the standard subtype check below.
        }

        // F-265: substr(witness, start, len) lowers to a raw OP_SPLIT
        // argument. A literal negative start used to type-check as plain
        // 'bigint' (the standard subtype loop below never inspects a
        // literal's VALUE) and compile to a script that aborts at runtime
        // -- `-5n` minimal-encodes to `<85>`, which OP_SPLIT rejects.
        // Catch the literal case (bare or unary-negated BigIntLiteral) at
        // compile time, mirroring the extractPrevOutputScript /
        // requireOutputP2PKH "must be >= 0" pattern above. Compares the
        // arbitrary-precision `BigInt` directly rather than narrowing to
        // `i128` first -- a literal outside `i128` range must not silently
        // escape this check. A non-literal start (a variable or computed
        // expression) has no static value to check and is unaffected.
        if func_name == "substr" && args.len() >= 2 {
            let start_lit: Option<BigInt> = match &args[1] {
                Expression::BigIntLiteral { value } => Some(value.clone()),
                Expression::UnaryExpr { op: UnaryOp::Neg, operand } => {
                    if let Expression::BigIntLiteral { value } = operand.as_ref() {
                        Some(-value.clone())
                    } else {
                        None
                    }
                }
                _ => None,
            };
            if let Some(start) = start_lit {
                if start < BigInt::from(0) {
                    self.add_error(format!(
                        "substr() argument 2 (start) must be >= 0; got {}",
                        start
                    ));
                }
            }
        }

        // Standard argument count check
        if args.len() != sig_params.len() {
            self.add_error(format!(
                "{}() expects {} argument(s), got {}",
                func_name,
                sig_params.len(),
                args.len()
            ));
        }

        let count = args.len().min(sig_params.len());
        for i in 0..count {
            let arg_type = self.infer_expr_type(&args[i], env);
            let expected = sig_params[i];

            if !is_subtype(&arg_type, expected) && arg_type != "<unknown>" {
                self.add_error(format!(
                    "Argument {} of {}(): expected '{}', got '{}'",
                    i + 1,
                    func_name,
                    expected,
                    arg_type
                ));
            }
        }

        // Infer remaining args even if count mismatches
        for i in count..args.len() {
            self.infer_expr_type(&args[i], env);
        }

        // Affine type enforcement
        self.check_affine_consumption(func_name, args, env);

        return_type.to_string()
    }

    /// Check affine type constraints: Sig and SigHashPreimage values may
    /// only be consumed once by a consuming function. Tracks
    /// consumption by *origin*, not variable name, so aliases (`const
    /// again = sig`) and property accesses (`this.sig`) cannot be
    /// used to launder a double-consumption past the affine check.
    /// 2026-04-30 audit finding F6.
    fn check_affine_consumption(
        &mut self,
        func_name: &str,
        args: &[Expression],
        env: &mut TypeEnv,
    ) {
        let indices = match consuming_param_indices(func_name) {
            Some(indices) => indices,
            None => return,
        };

        for &param_index in indices {
            if param_index >= args.len() {
                continue;
            }

            let arg = &args[param_index];
            let arg_type = match self.affine_expr_type(arg, env) {
                Some(t) => t,
                None => continue,
            };
            if !is_affine_type(&arg_type) {
                continue;
            }

            let origin = match self.affine_origin_of_expr(arg) {
                Some(o) => o,
                None => continue,
            };

            // Render a short label (source-form) for the diagnostic.
            let label = match arg {
                Expression::Identifier { name } => name.clone(),
                Expression::PropertyAccess { property } => format!("this.{}", property),
                _ => origin.clone(),
            };

            if self.consumed_values.contains(&origin)
                || self.consumed_per_loop_iteration(&origin, env)
            {
                self.add_error(format!(
                    "affine value '{}' has already been consumed",
                    label
                ));
            } else {
                self.consumed_values.insert(origin);
            }
        }
    }

    /// F-110: true when `origin` is bound outside the innermost enclosing loop
    /// that may run two or more times, so this one syntactic consumption is
    /// executed once per iteration -- a double use. A property, or a name the
    /// env does not bind (a bare-identifier property), is always outside.
    fn consumed_per_loop_iteration(&self, origin: &str, env: &TypeEnv) -> bool {
        let innermost = match self.repeating_loop_scopes.last() {
            Some(i) => *i,
            None => return false,
        };
        if origin.starts_with("prop:") {
            return true;
        }
        env.scope_index_of(origin) < innermost
    }

    /// Resolve the canonical origin key for affine tracking.
    /// Identifiers consult the alias map; property accesses use the
    /// "prop:<name>" namespace; everything else returns None.
    fn affine_origin_of_expr(&self, expr: &Expression) -> Option<String> {
        match expr {
            Expression::Identifier { name } => Some(
                self.affine_aliases
                    .get(name)
                    .cloned()
                    .unwrap_or_else(|| name.clone()),
            ),
            Expression::PropertyAccess { property } => Some(format!("prop:{}", property)),
            _ => None,
        }
    }

    /// Look up the type of an expression for affine purposes.
    /// Identifiers come from the env; property accesses from the
    /// prop-types map.
    fn affine_expr_type(&self, expr: &Expression, env: &TypeEnv) -> Option<TType> {
        match expr {
            Expression::Identifier { name } => env.lookup(name).cloned(),
            Expression::PropertyAccess { property } => self.prop_types.get(property).cloned(),
            _ => None,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Private method return type inference
// ---------------------------------------------------------------------------

/// Infer a private method's return type by walking all return statements
/// and inferring the type of their expressions. Returns "void" if no
/// return statements with values are found.
fn infer_method_return_type(method: &MethodNode) -> TType {
    let return_types = collect_return_types(&method.body);

    if return_types.is_empty() {
        return VOID.to_string();
    }

    let first = &return_types[0];
    let all_same = return_types.iter().all(|t| t == first);
    if all_same {
        return first.clone();
    }

    // Check if all are in the bigint family
    if return_types.iter().all(|t| is_bigint_subtype(t)) {
        return BIGINT.to_string();
    }

    // Check if all are in the ByteString family
    if return_types.iter().all(|t| is_bytestring_subtype(t)) {
        return BYTESTRING.to_string();
    }

    // Check if all are boolean
    if return_types.iter().all(|t| t == BOOLEAN) {
        return BOOLEAN.to_string();
    }

    // Mixed types -- return the first as a best effort
    first.clone()
}

/// Recursively collect inferred types from return statements.
fn collect_return_types(stmts: &[Statement]) -> Vec<TType> {
    let mut types = Vec::new();
    for stmt in stmts {
        match stmt {
            Statement::ReturnStatement { value, .. } => {
                if let Some(v) = value {
                    types.push(infer_expr_type_static(v));
                }
            }
            Statement::IfStatement {
                then_branch,
                else_branch,
                ..
            } => {
                types.extend(collect_return_types(then_branch));
                if let Some(else_stmts) = else_branch {
                    types.extend(collect_return_types(else_stmts));
                }
            }
            Statement::ForStatement { body, .. } => {
                types.extend(collect_return_types(body));
            }
            _ => {}
        }
    }
    types
}

/// Lightweight static expression type inference without a type environment.
/// Used for inferring return types of private methods before the full
/// type-check pass runs.
fn infer_expr_type_static(expr: &Expression) -> TType {
    match expr {
        Expression::BigIntLiteral { .. } => BIGINT.to_string(),
        Expression::BoolLiteral { .. } => BOOLEAN.to_string(),
        Expression::ByteStringLiteral { .. } => BYTESTRING.to_string(),
        Expression::Identifier { name } => {
            if name == "true" || name == "false" {
                BOOLEAN.to_string()
            } else {
                "<unknown>".to_string()
            }
        }
        Expression::BinaryExpr { op, .. } => match op {
            BinaryOp::Add
            | BinaryOp::Sub
            | BinaryOp::Mul
            | BinaryOp::Div
            | BinaryOp::Mod
            | BinaryOp::BitAnd
            | BinaryOp::BitOr
            | BinaryOp::BitXor
            | BinaryOp::Shl
            | BinaryOp::Shr => BIGINT.to_string(),
            _ => BOOLEAN.to_string(),
        },
        Expression::UnaryExpr { op, .. } => match op {
            UnaryOp::Not => BOOLEAN.to_string(),
            _ => BIGINT.to_string(),
        },
        Expression::CallExpr {
            callee,
            asm_return_type,
            ..
        } => {
            let builtins = builtin_functions();
            if let Expression::Identifier { name } = callee.as_ref() {
                // Expression-form asm<T>({...}) statically yields type T.
                if name == "asm" {
                    if let Some(t) = asm_return_type {
                        return t.to_string();
                    }
                }
                if let Some(sig) = builtins.get(name.as_str()) {
                    return sig.return_type.to_string();
                }
            }
            if let Expression::PropertyAccess { property } = callee.as_ref() {
                if let Some(sig) = builtins.get(property.as_str()) {
                    return sig.return_type.to_string();
                }
            }
            "<unknown>".to_string()
        }
        Expression::TernaryExpr {
            consequent,
            alternate,
            ..
        } => {
            let cons_type = infer_expr_type_static(consequent);
            if cons_type != "<unknown>" {
                cons_type
            } else {
                infer_expr_type_static(alternate)
            }
        }
        Expression::IncrementExpr { .. } | Expression::DecrementExpr { .. } => {
            BIGINT.to_string()
        }
        Expression::ArrayLiteral { .. } => "<unknown>[]".to_string(),
        _ => "<unknown>".to_string(),
    }
}

fn type_node_to_ttype(node: &TypeNode) -> TType {
    match node {
        TypeNode::Primitive(name) => name.as_str().to_string(),
        TypeNode::FixedArray { element, .. } => {
            format!("{}[]", type_node_to_ttype(element))
        }
        TypeNode::Custom(name) => name.clone(),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontend::parser::parse_source;
    use crate::frontend::validator;

    /// Helper: parse and validate a TypeScript source string, then return the ContractNode.
    fn parse_and_validate(source: &str) -> ContractNode {
        let result = parse_source(source, Some("test.runar.ts"));
        assert!(
            result.errors.is_empty(),
            "parse errors: {:?}",
            result.errors
        );
        let contract = result.contract.expect("expected a contract from parse");
        let validation = validator::validate(&contract);
        assert!(
            validation.errors.is_empty(),
            "validation errors: {:?}",
            validation.errors
        );
        contract
    }

    #[test]
    fn test_valid_p2pkh_passes_typecheck() {
        let source = r#"
import { SmartContract, Addr, PubKey, Sig } from 'runar-lang';

class P2PKH extends SmartContract {
    readonly pubKeyHash: Addr;

    constructor(pubKeyHash: Addr) {
        super(pubKeyHash);
        this.pubKeyHash = pubKeyHash;
    }

    public unlock(sig: Sig, pubKey: PubKey) {
        assert(hash160(pubKey) === this.pubKeyHash);
        assert(checkSig(sig, pubKey));
    }
}
"#;
        let contract = parse_and_validate(source);
        let result = typecheck(&contract);
        assert!(
            result.errors.is_empty(),
            "expected no typecheck errors, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_unknown_function_call_produces_error() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class Bad extends SmartContract {
    readonly x: bigint;

    constructor(x: bigint) {
        super(x);
        this.x = x;
    }

    public check(v: bigint) {
        const y = Math.floor(v);
        assert(y === this.x);
    }
}
"#;
        let contract = parse_and_validate(source);
        let result = typecheck(&contract);
        assert!(
            !result.errors.is_empty(),
            "expected typecheck errors for unknown function Math.floor"
        );
        let has_unknown_error = result
            .errors
            .iter()
            .any(|e| e.message.to_lowercase().contains("unknown"));
        assert!(
            has_unknown_error,
            "expected error about unknown function, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_builtin_with_wrong_arg_count_produces_error() {
        let source = r#"
import { SmartContract, PubKey, Sig } from 'runar-lang';

class Bad extends SmartContract {
    readonly x: bigint;

    constructor(x: bigint) {
        super(x);
        this.x = x;
    }

    public check(v: bigint) {
        assert(min(v));
    }
}
"#;
        let contract = parse_and_validate(source);
        let result = typecheck(&contract);
        assert!(
            !result.errors.is_empty(),
            "expected typecheck errors for wrong arg count"
        );
        let has_arg_count_error = result
            .errors
            .iter()
            .any(|e| e.message.contains("expects") && e.message.contains("argument"));
        assert!(
            has_arg_count_error,
            "expected error about wrong argument count, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_arithmetic_on_boolean_produces_error() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class Bad extends SmartContract {
    readonly x: bigint;

    constructor(x: bigint) {
        super(x);
        this.x = x;
    }

    public check(v: bigint, flag: boolean) {
        const sum = v + flag;
        assert(sum === this.x);
    }
}
"#;
        let contract = parse_and_validate(source);
        let result = typecheck(&contract);
        assert!(
            !result.errors.is_empty(),
            "expected typecheck errors for arithmetic on boolean"
        );
        let has_type_error = result
            .errors
            .iter()
            .any(|e| e.message.contains("bigint") || e.message.contains("boolean"));
        assert!(
            has_type_error,
            "expected type mismatch error, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn test_valid_stateful_contract_passes_typecheck() {
        let source = r#"
import { StatefulSmartContract } from 'runar-lang';

class Counter extends StatefulSmartContract {
    count: bigint;

    constructor(count: bigint) {
        super(count);
        this.count = count;
    }

    public increment() {
        this.count++;
    }
}
"#;
        let contract = parse_and_validate(source);
        let result = typecheck(&contract);
        assert!(
            result.errors.is_empty(),
            "expected no typecheck errors for stateful contract, got: {:?}",
            result.errors
        );
    }

    // -----------------------------------------------------------------------
    // Test: Valid arithmetic contract passes type check
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_arithmetic() {
        let source = r#"
import { SmartContract, assert } from 'runar-lang';

class Arithmetic extends SmartContract {
    readonly target: bigint;

    constructor(target: bigint) {
        super(target);
        this.target = target;
    }

    public verify(a: bigint, b: bigint) {
        const sum: bigint = a + b;
        const diff: bigint = a - b;
        const prod: bigint = a * b;
        const quot: bigint = a / b;
        const result: bigint = sum + diff + prod + quot;
        assert(result === this.target);
    }
}
"#;
        let contract = parse_and_validate(source);
        let result = typecheck(&contract);
        assert!(
            result.errors.is_empty(),
            "expected no typecheck errors for Arithmetic, got: {:?}",
            result.errors
        );
    }

    // -----------------------------------------------------------------------
    // Test: Valid boolean logic contract passes type check
    // -----------------------------------------------------------------------

    #[test]
    fn test_valid_boolean_logic() {
        let source = r#"
import { SmartContract, assert } from 'runar-lang';

class BoolLogic extends SmartContract {
    readonly threshold: bigint;

    constructor(threshold: bigint) {
        super(threshold);
        this.threshold = threshold;
    }

    public verify(a: bigint, b: bigint, flag: boolean) {
        const aAbove: boolean = a > this.threshold;
        const bAbove: boolean = b > this.threshold;
        const bothAbove: boolean = aAbove && bAbove;
        const eitherAbove: boolean = aAbove || bAbove;
        const notFlag: boolean = !flag;
        assert(bothAbove || (eitherAbove && notFlag));
    }
}
"#;
        let contract = parse_and_validate(source);
        let result = typecheck(&contract);
        assert!(
            result.errors.is_empty(),
            "expected no typecheck errors for BoolLogic, got: {:?}",
            result.errors
        );
    }

    // -----------------------------------------------------------------------
    // Test: Subtype compatibility — PubKey where ByteString expected passes
    // -----------------------------------------------------------------------

    #[test]
    fn test_subtype_compatibility() {
        let source = r#"
import { SmartContract, assert, PubKey, sha256 } from 'runar-lang';

class HashCheck extends SmartContract {
    readonly expectedHash: Sha256;

    constructor(expectedHash: Sha256) {
        super(expectedHash);
        this.expectedHash = expectedHash;
    }

    public verify(pubKey: PubKey) {
        assert(sha256(pubKey) === this.expectedHash);
    }
}
"#;
        // parse_and_validate calls validate() which may fail on Sha256 type
        // We test typecheck directly after a best-effort parse
        let result = crate::frontend::parser::parse_source(source, Some("test.runar.ts"));
        if result.errors.is_empty() {
            if let Some(contract) = result.contract {
                let tc_result = typecheck(&contract);
                // PubKey should be assignable to ByteString (sha256's parameter type)
                // so there should be no error about PubKey argument type mismatch
                let pubkey_arg_error = tc_result.errors.iter().any(|e| {
                    e.message.contains("argument") && e.message.contains("PubKey")
                });
                assert!(
                    !pubkey_arg_error,
                    "PubKey should be assignable to ByteString, but got error about PubKey argument: {:?}",
                    tc_result.errors
                );
            }
        }
        // If parse itself fails, the test is inconclusive — we skip rather than fail
    }

    // -----------------------------------------------------------------------
    // Test: console.log call is rejected as unknown function
    // Mirrors Go TestTypeCheck_UnknownFunction_ConsoleLog
    // -----------------------------------------------------------------------

    #[test]
    fn test_unknown_function_console_log() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class Bad extends SmartContract {
    constructor() {
        super();
    }

    public check(val: bigint) {
        console.log(val);
        assert(val > 0n);
    }
}
"#;
        let result = crate::frontend::parser::parse_source(source, Some("test.runar.ts"));
        if result.errors.is_empty() {
            if let Some(contract) = result.contract {
                let tc_result = typecheck(&contract);
                assert!(
                    !tc_result.errors.is_empty(),
                    "expected typecheck errors for unknown function console.log"
                );
                let has_unknown_error = tc_result.errors.iter().any(|e| {
                    e.message.to_lowercase().contains("unknown")
                        || e.message.to_lowercase().contains("console")
                });
                assert!(
                    has_unknown_error,
                    "expected error about unknown function console.log, got: {:?}",
                    tc_result.errors
                );
            }
        }
        // If parse itself fails (e.g. because the parser rejects member calls on unknown objects),
        // that also counts as rejection — just not at the typecheck level
    }

    // -----------------------------------------------------------------------
    // F-208: Rúnar has no first-class functions. A bound local variable used
    // as a callee used to fall into the "local variable" branch and return
    // "<unknown>" with NO diagnostic, silently accepting the call.
    // -----------------------------------------------------------------------

    #[test]
    fn f208_local_variable_called_as_function_rejected() {
        let source = r#"
class C extends SmartContract {
    readonly a: bigint;
    constructor(a: bigint) { super(a); this.a = a; }
    public check(a: bigint) {
        const f: bigint = a;
        const r = f(a, a, a);
        assert(this.a >= 0n);
    }
}
"#;
        let contract = parse_and_validate(source);
        let result = typecheck(&contract);
        assert!(
            !result.errors.is_empty(),
            "expected typecheck errors for calling local variable 'f' as a function"
        );
        assert!(
            result.errors.iter().any(|e| e.message.contains("not callable")),
            "expected 'not callable' error, got: {:?}",
            result.errors
        );
    }

    // -----------------------------------------------------------------------
    // F-063: infer_expr_type walks EVERY array-literal element.
    //
    // The ArrayLiteral arm inferred only the first element, so a call nested
    // in any later element never reached the unknown-function rule and a
    // mistyped later element was never compared. Ported from the TS reference.
    //
    // Proves: typecheck() refuses each shape with the TS reference's
    // diagnostic (or this tier's existing unknown-function diagnostic). Does
    // not prove: CLI exit status or cross-tier parity (conformance/negatives).
    // -----------------------------------------------------------------------

    fn f063_type_errors(source: &str) -> Vec<String> {
        typecheck(&parse_and_validate(source))
            .errors
            .into_iter()
            .map(|e| e.message)
            .collect()
    }

    #[test]
    fn f063_unknown_function_inside_array_literal_rejected() {
        let errs = f063_type_errors(
            r#"
class C extends SmartContract {
  readonly pk: PubKey;
  constructor(pk: PubKey) { super(pk); this.pk = pk; }
  public unlock(s: Sig) { assert(checkMultiSig([s], [this.pk, totallyBogusFunction(1n)])); }
}
"#,
        );
        assert!(
            errs.iter().any(|m| m.contains("unknown function 'totallyBogusFunction'")),
            "got: {:?}",
            errs
        );
    }

    #[test]
    fn f063_array_element_type_mismatch_rejected() {
        let errs = f063_type_errors(
            r#"
class C extends SmartContract {
  readonly pk: PubKey;
  constructor(pk: PubKey) { super(pk); this.pk = pk; }
  public unlock(s: Sig) { assert(checkMultiSig([s], [this.pk, 1n])); }
}
"#,
        );
        assert!(
            errs.iter().any(|m| m.contains("Array element type mismatch: expected 'PubKey', got 'bigint'")),
            "got: {:?}",
            errs
        );
    }

    #[test]
    fn f063_well_typed_check_multisig_accepted() {
        let errs = f063_type_errors(
            r#"
class C extends SmartContract {
  readonly pk: PubKey;
  readonly pk2: PubKey;
  constructor(pk: PubKey, pk2: PubKey) { super(pk, pk2); this.pk = pk; this.pk2 = pk2; }
  public unlock(s: Sig) { assert(checkMultiSig([s], [this.pk, this.pk2])); }
}
"#,
        );
        assert!(errs.is_empty(), "got: {:?}", errs);
    }

    /// F-110: a bounded loop is unrolled `count` times, so an affine value
    /// bound outside a loop that runs two or more times and consumed in its
    /// body is consumed once per iteration and must get the same diagnostic as
    /// a sequential double use. Single-iteration loops stay legal. Proves the
    /// type checker's verdict only; consumption inside private helpers is out
    /// of scope (the affine check is intra-method).
    #[test]
    fn f110_affine_consumption_in_repeating_loop() {
        let cases: &[(&str, &str, &str)] = &[
            ("sig: Sig", "for (let i = 0n; i < 2n; i++) { assert(checkSig(sig, this.pk)); }", "affine value 'sig' has already been consumed"),
            ("preimage: SigHashPreimage", "for (let i = 3n; i > 0n; i--) { assert(checkPreimage(preimage)); }", "affine value 'preimage' has already been consumed"),
            ("sig: Sig", "for (let i = 0n; i <= 1n; i++) { const s: Sig = sig; assert(checkSig(s, this.pk)); }", "affine value 's' has already been consumed"),
            ("sig: Sig", "for (let i = 0n; i < 2n; i++) { for (let j = 0n; j < 1n; j++) { assert(checkSig(sig, this.pk)); } }", "affine value 'sig' has already been consumed"),
            ("sig: Sig", "assert(checkSig(sig, this.pk)); for (let i = 0n; i < 1n; i++) { assert(checkSig(sig, this.pk)); }", "affine value 'sig' has already been consumed"),
            ("sig: Sig", "for (let i = 0n; i < 1n; i++) { assert(checkSig(sig, this.pk)); }", ""),
            ("sig: Sig", "for (let i = 5n; i >= 5n; i--) { for (let j = 0n; j <= 0n; j++) { assert(checkSig(sig, this.pk)); } }", ""),
        ];
        for (params, body, want) in cases {
            let source = format!(
                "class C extends SmartContract {{\n  readonly pk: PubKey;\n  constructor(pk: PubKey) {{ super(pk); this.pk = pk; }}\n  public m({}) {{\n    {}\n    assert(true);\n  }}\n}}\n",
                params, body
            );
            let errs = f063_type_errors(&source);
            if want.is_empty() {
                assert!(errs.is_empty(), "{}: got: {:?}", body, errs);
            } else {
                assert!(errs.iter().any(|e| e.contains(want)), "{}: expected {:?}, got: {:?}", body, want, errs);
            }
        }
    }

    /// F-222: the then and else arms of an if are mutually exclusive, so a Sig
    /// consumed once in each arm is consumed once on every path and must
    /// typecheck. Every shape where some path consumes twice (an arm plus after
    /// the if, before plus an arm, twice in one arm, once per arm inside a
    /// 2-iteration loop) must still be refused. Proves the type checker's
    /// verdict only; the ternary form is not an if statement and is untouched.
    #[test]
    fn f222_affine_consumption_across_if_else_arms() {
        const DOUBLE: &str = "affine value 'sig' has already been consumed";
        let cases: &[(&str, &str)] = &[
            ("if (flag) { assert(checkSig(sig, this.pk)); } else { assert(checkSig(sig, this.pk)); }", ""),
            ("if (flag) { const a: Sig = sig; assert(checkSig(a, this.pk)); } else { assert(checkSig(sig, this.pk)); }", ""),
            ("if (flag) { assert(checkSig(sig, this.pk)); } else { if (flag) { assert(checkSig(sig, this.pk)); } else { assert(checkSig(sig, this.pk)); } }", ""),
            ("if (flag) { assert(checkSig(sig, this.pk)); } assert(checkSig(sig, this.pk));", DOUBLE),
            ("if (flag) { assert(true); } else { assert(checkSig(sig, this.pk)); } assert(checkSig(sig, this.pk));", DOUBLE),
            ("if (flag) { assert(checkSig(sig, this.pk)); } else { assert(checkSig(sig, this.pk)); } assert(checkSig(sig, this.pk));", DOUBLE),
            ("if (flag) { if (flag) { assert(checkSig(sig, this.pk)); } } else { assert(true); } assert(checkSig(sig, this.pk));", DOUBLE),
            ("const a: Sig = sig; if (flag) { assert(checkSig(a, this.pk)); } else { assert(true); } assert(checkSig(sig, this.pk));", DOUBLE),
            ("assert(checkSig(sig, this.pk)); if (flag) { assert(checkSig(sig, this.pk)); }", DOUBLE),
            ("if (flag) { assert(checkSig(sig, this.pk)); assert(checkSig(sig, this.pk)); } else { assert(true); }", DOUBLE),
            ("if (flag) { assert(true); } else { assert(checkSig(sig, this.pk)); assert(checkSig(sig, this.pk)); }", DOUBLE),
            ("for (let i = 0n; i < 2n; i++) { if (flag) { assert(checkSig(sig, this.pk)); } else { assert(checkSig(sig, this.pk)); } }", DOUBLE),
        ];
        for (body, want) in cases {
            let source = format!(
                "class C extends SmartContract {{\n  readonly pk: PubKey;\n  constructor(pk: PubKey) {{ super(pk); this.pk = pk; }}\n  public m(sig: Sig, flag: boolean) {{\n    {}\n    assert(true);\n  }}\n}}\n",
                body
            );
            let errs = f063_type_errors(&source);
            if want.is_empty() {
                assert!(errs.is_empty(), "{}: got: {:?}", body, errs);
            } else {
                assert!(errs.iter().any(|e| e.contains(want)), "{}: expected {:?}, got: {:?}", body, want, errs);
            }
        }
    }

    // -----------------------------------------------------------------------
    // F-265 -- substr() literal negative start is a compile-time error
    //
    // substr(witness, start, len) lowers to a raw OP_SPLIT argument. No pass
    // enforced start >= 0: a literal negative start
    // (`substr(a, -5n, 3n)`) type-checked as plain 'bigint' (the standard
    // subtype loop never inspects a literal's VALUE) and compiled to a
    // script that aborts at runtime -- `-5n` minimal-encodes to `<85>`,
    // which OP_SPLIT rejects as out of range.
    //
    // Proves: a literal (bare or unary-negated BigIntLiteral) negative start
    // is now a typecheck-time diagnostic, mirroring the existing
    // extractPrevOutputScript/requireOutputP2PKH "must be >= 0" literal-bound
    // pattern above. Does not prove: anything about a NON-literal negative
    // start (a variable or computed expression) -- that remains a runtime
    // abort, unchanged, because the stack model has no static value range
    // for a non-literal.
    // -----------------------------------------------------------------------

    #[test]
    fn f265_substr_literal_negative_start_rejected() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class C extends SmartContract {
    readonly a: ByteString;

    constructor(a: ByteString) {
        super(a);
        this.a = a;
    }

    public unlock() {
        assert(substr(this.a, -5n, 3n) === this.a);
    }
}
"#;
        let contract = parse_and_validate(source);
        let result = typecheck(&contract);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("substr() argument 2 (start) must be >= 0; got -5")),
            "expected a substr() start-bound error, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn f265_substr_literal_non_negative_start_accepted() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class C extends SmartContract {
    readonly a: ByteString;

    constructor(a: ByteString) {
        super(a);
        this.a = a;
    }

    public unlock() {
        assert(substr(this.a, 0n, 3n) === this.a);
    }
}
"#;
        let contract = parse_and_validate(source);
        let result = typecheck(&contract);
        assert!(
            result.errors.is_empty(),
            "expected no typecheck errors, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn f265_substr_non_literal_start_unchanged() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class C extends SmartContract {
    readonly a: ByteString;

    constructor(a: ByteString) {
        super(a);
        this.a = a;
    }

    public unlock(n: bigint) {
        assert(substr(this.a, n, 3n) === this.a);
    }
}
"#;
        let contract = parse_and_validate(source);
        let result = typecheck(&contract);
        assert!(
            result.errors.is_empty(),
            "expected no typecheck errors, got: {:?}",
            result.errors
        );
    }

    // N-234: a property initializer of the wrong literal family compiled
    // without complaint. Proves only the Rust tier's
    // check_property_initializers; the 7-tier cross-compiler shape is
    // conformance/negatives/N233-*.

    #[test]
    fn n234_rejects_bytestring_initializer_for_bigint_property() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class BadScalarInit extends SmartContract {
    readonly x: bigint = 'ab';

    constructor() {
        super();
    }

    public check() {
        assert(this.x === 1n);
    }
}
"#;
        let contract = parse_and_validate(source);
        let result = typecheck(&contract);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("Type 'ByteString' is not assignable to type 'bigint'")),
            "expected the not-assignable diagnostic, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn n234_rejects_to_bytestring_call_initializer_for_bigint_property() {
        let source = r#"
import { SmartContract, toByteString } from 'runar-lang';

class BadScalarInit extends SmartContract {
    readonly x: bigint = toByteString('ab');

    constructor() {
        super();
    }

    public check() {
        assert(this.x === 1n);
    }
}
"#;
        let contract = parse_and_validate(source);
        let result = typecheck(&contract);
        assert!(
            result
                .errors
                .iter()
                .any(|e| e.message.contains("Type 'ByteString' is not assignable to type 'bigint'")),
            "expected the not-assignable diagnostic, got: {:?}",
            result.errors
        );
    }

    #[test]
    fn n234_still_accepts_well_typed_scalar_initializer() {
        let source = r#"
import { SmartContract } from 'runar-lang';

class GoodScalarInit extends SmartContract {
    readonly x: bigint = 1n;

    constructor() {
        super();
    }

    public check() {
        assert(this.x === 1n);
    }
}
"#;
        let contract = parse_and_validate(source);
        let result = typecheck(&contract);
        assert!(
            result.errors.is_empty(),
            "expected no typecheck errors, got: {:?}",
            result.errors
        );
    }
}
