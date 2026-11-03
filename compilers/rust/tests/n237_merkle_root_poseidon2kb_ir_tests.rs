//! N-237: `merkleRootPoseidon2KB` through the Rust `--ir` entry point.
//!
//! The Rust source path refuses this builtin as Go-only (F-387), but `--ir`
//! runs no typecheck. `ir/loader.rs` already accepts the builtin's variadic
//! `8*depth + 10` arity, yet `codegen/stack.rs` routed it through
//! `lower_merkle_root` — the SHA-256 Merkle lowering, which asserts exactly 4
//! arguments — so Go's own IR for a depth-1 probe died with
//! "merkleRootPoseidon2KB requires exactly 4 arguments (leaf, proof, index,
//! depth)" and `poseidon2_merkle::emit_poseidon2_merkle_root` was unreachable.
//!
//! Under the Go-only-parity policy (conformance/go-only-parity/, R-037) a
//! non-Go port must match Go byte for byte or refuse. This tier now matches
//! Go, as the Python tier does (F-092): the lowering mirrors Go's
//! `lowerMerkleRootPoseidon2KB` (depth 1..=32 per Go R-172, exact arity) and
//! packs the eight root limbs base-2^32 like Go's `EmitPoseidon2RootPack`.
//!
//! What this proves: Rust `--ir` now COMPILES Go's IR shape for the depth-1
//! probe, the emitted script ends with Go's `EmitPoseidon2RootPack` fold
//! (7 x `push 2^32, OP_MUL, OP_ADD`) feeding the equality — so all eight root
//! limbs reach the comparison, not root_7 alone behind seven OP_NIPs — and the
//! depth-bound and arity refusals name the builtin.
//!
//! What it does not prove: byte-identity with Go (that is the F-092 `--ir` leg
//! of conformance/go-only-parity/go-only-parity.test.ts, which compares this
//! tier's hex against Go's on Go's own `--emit-ir`), nor execution semantics.
//! The script is not executed here: the Rust bsv-sdk 0.2.x `Spend` still
//! treats OP_2MUL (used by the shared KoalaBear field codegen) as disabled, so
//! it cannot run this family. Execution is covered by Go's
//! compilers/go/compiler/poseidon2_merkle_root_binding_test.go (Plonky3
//! vectors) on the bytes this tier is held identical to. Depths > 1 are not
//! exercised.

use runar_compiler_rust::compile_from_ir_str;
use serde_json::{json, Value};

/// ANF IR for `assert(merkleRootPoseidon2KB(l0..l7, s0_0..s0_7, idx, depth) === expected)`,
/// the shape the Go tier emits for conformance/go-only-parity/GoOnlyPoseidon2Merkle.runar.ts.
/// `extra_args` appends that many extra param loads to the call, to probe the arity gate.
fn probe_ir(depth: i64, extra_args: usize) -> String {
    let mut names: Vec<String> = (0..8).map(|i| format!("l{}", i)).collect();
    names.extend((0..8).map(|i| format!("s0_{}", i)));
    names.extend((0..extra_args).map(|i| format!("x{}", i)));
    names.push("idx".into());
    let mut params: Vec<Value> = names.iter().map(|n| json!({"name": n, "type": "bigint"})).collect();
    params.push(json!({"name": "expected", "type": "bigint"}));

    let mut body: Vec<Value> = names
        .iter()
        .enumerate()
        .map(|(i, n)| json!({"name": format!("t{}", i), "value": {"kind": "load_param", "name": n}}))
        .collect();
    let k = names.len();
    body.push(json!({"name": format!("t{}", k), "value": {"kind": "load_const", "value": depth}}));
    let call_args: Vec<String> = (0..=k).map(|i| format!("t{}", i)).collect();
    body.push(json!({"name": format!("t{}", k + 1),
        "value": {"kind": "call", "func": "merkleRootPoseidon2KB", "args": call_args}}));
    body.push(json!({"name": format!("t{}", k + 2), "value": {"kind": "load_param", "name": "expected"}}));
    body.push(json!({"name": format!("t{}", k + 3),
        "value": {"kind": "bin_op", "op": "===", "left": format!("t{}", k + 1), "right": format!("t{}", k + 2)}}));
    body.push(json!({"name": format!("t{}", k + 4), "value": {"kind": "assert", "value": format!("t{}", k + 3)}}));

    json!({
        "contractName": "P2KBRootBinding",
        "parentClass": "SmartContract",
        "properties": [],
        "methods": [
            {"name": "constructor", "isPublic": false, "params": [],
             "body": [{"name": "t0", "value": {"kind": "call", "func": "super", "args": []}}]},
            {"name": "verify", "isPublic": true, "params": params, "body": body},
        ],
    })
    .to_string()
}

/// Go's `EmitPoseidon2RootPack`: 7 x (push 2^32 = `05 0000000001`, OP_MUL, OP_ADD).
const ROOT_PACK_HEX: &str = "0500000000019593";

#[test]
fn go_ir_for_depth_1_compiles() {
    compile_from_ir_str(&probe_ir(1, 0))
        .unwrap_or_else(|e| panic!("Rust --ir must compile Go's merkleRootPoseidon2KB IR: {}", e));
}

#[test]
fn all_eight_root_limbs_are_packed_into_the_comparison() {
    let script = compile_from_ir_str(&probe_ir(1, 0))
        .unwrap_or_else(|e| panic!("Rust --ir must compile Go's merkleRootPoseidon2KB IR: {}", e))
        .script;
    // pack, then bring `expected` up (OP_SWAP) and compare (OP_NUMEQUAL) as the
    // terminal assert -- exactly Go's tail for this probe.
    let tail = format!("{}7c9c", ROOT_PACK_HEX.repeat(7));
    assert!(
        script.ends_with(&tail),
        "script must end with the 8-limb base-2^32 pack feeding the equality; tail was ...{}",
        &script[script.len().saturating_sub(tail.len() + 16)..]
    );
    // The pre-fix truncation shape (seven OP_NIPs straight into the compare) must be absent.
    assert!(!script.ends_with(&format!("{}7c9c", "77".repeat(7))));
}

#[test]
fn depth_above_32_is_refused_by_name() {
    // Go R-172 / Python F-260: the emitter's bound is 32, so the lowering gate is 32.
    let err = compile_from_ir_str(&probe_ir(33, 0)).expect_err("depth 33 must be refused");
    assert!(
        err.contains("merkleRootPoseidon2KB") && err.contains("between 1 and 32"),
        "diagnostic must name the builtin and its 1..32 bound: {}",
        err
    );
}

#[test]
fn arity_not_matching_depth_is_refused_by_name() {
    // 8 extra args keeps the loader's (n - 10) % 8 == 0 shape but claims depth 1.
    let err = compile_from_ir_str(&probe_ir(1, 8)).expect_err("26 args at depth 1 must be refused");
    assert!(
        err.contains("merkleRootPoseidon2KB") && err.contains("expected 18 arguments"),
        "diagnostic must name the builtin and the arity depth implies: {}",
        err
    );
}
