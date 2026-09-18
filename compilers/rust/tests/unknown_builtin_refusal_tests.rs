//! R-016 regression guard for the Rust tier.
//!
//! `lower_call`'s general-builtin tail used to end with:
//!
//! ```text
//! } else {
//!     // Unknown function -- push a placeholder
//!     self.emit_op(StackOp::Push(PushValue::Int(BigInt::from(0))));
//!     self.sm.push(binding_name);
//!     return;
//! }
//! ```
//!
//! Two distinct defects came out of that one branch:
//!
//!   1. **The call's semantics silently became the constant `0`.** No
//!      diagnostic, exit status 0. For a P2PKH whose `hash160` was swapped
//!      for an unresolvable name, the emitted script was
//!      `OP_DUP OP_0 OP_0 OP_EQUALVERIFY OP_CHECKSIG` (`76000088ac`) instead
//!      of `OP_DUP OP_HASH160 OP_0 OP_EQUALVERIFY OP_CHECKSIG` (`76a90088ac`)
//!      — the key-to-hash binding, the entire point of the contract, deleted
//!      and replaced by a comparison of two zeroes that always passes.
//!
//!   2. **The stack model desynced by `args.len()`.** The tail brings every
//!      argument physically to the top of the stack and then pops
//!      `args.len()` entries from the MODEL, on the assumption that the
//!      opcodes about to be emitted will consume them. On the unknown-name
//!      path no opcodes were emitted, so the values stayed on the real stack
//!      while the model believed they were gone. Every subsequent `OP_ROLL` /
//!      `OP_PICK` depth in that method was computed against a model that was
//!      short by `args.len()` — visible above as `OP_CHECKSIG` receiving the
//!      duplicated pubkey as its signature operand.
//!
//! The type checker rejects unknown functions on the SOURCE path, so this was
//! reachable through `--ir` (which runs no frontend validation in this tier).
//!
//! Eleven sibling refusals in the same file already panic with a named
//! diagnostic when a name does not resolve (`unknown binary operator`,
//! `unknown unary operator`, `unknown extractor`, `unknown EC builtin`,
//! `unknown NIST EC builtin`, `unknown Baby Bear builtin`, `unknown KoalaBear
//! builtin`, `unknown BN254 builtin`, `unknown Merkle builtin`,
//! `deserialize_state: unsupported type`, and the property-slot refusal).
//! Pass 5 wraps itself in `crate::refusal::catch_refusal`, so a panic surfaces
//! to the caller as a clean `Err` diagnostic. This tail was the outlier.
//!
//! Defect (2) is covered here **by elimination**: the refusal happens before
//! the placeholder push, and `lower_to_stack` discards the whole method on
//! `Err`, so no `StackMethod` carrying a desynced model can be produced at
//! all. The positive controls pin the surviving path — a known 1-arg and a
//! known 2-arg builtin still consume their arguments and emit their golden
//! bytes — so the fix cannot be satisfied by refusing everything.

use runar_compiler_rust::codegen::stack::lower_to_stack;
use runar_compiler_rust::ir::loader::load_ir_from_str;

/// The `basic-p2pkh` conformance fixture's ANF, with the hashing builtin
/// parameterised. `{FUNC}` = `hash160` is the real contract.
fn p2pkh_anf(hash_fn: &str) -> String {
    format!(
        r#"{{
  "contractName": "P2PKH",
  "properties": [
    {{ "name": "pubKeyHash", "type": "Addr", "readonly": true }}
  ],
  "methods": [
    {{
      "name": "unlock",
      "params": [
        {{ "name": "sig", "type": "Sig" }},
        {{ "name": "pubKey", "type": "PubKey" }}
      ],
      "body": [
        {{ "name": "t0", "value": {{ "kind": "load_param", "name": "pubKey" }} }},
        {{ "name": "t1", "value": {{ "kind": "call", "func": "{hash_fn}", "args": ["t0"] }} }},
        {{ "name": "t2", "value": {{ "kind": "load_prop", "name": "pubKeyHash" }} }},
        {{ "name": "t3", "value": {{ "kind": "bin_op", "op": "===", "left": "t1", "right": "t2", "result_type": "bytes" }} }},
        {{ "name": "t4", "value": {{ "kind": "assert", "value": "t3" }} }},
        {{ "name": "t5", "value": {{ "kind": "load_param", "name": "sig" }} }},
        {{ "name": "t6", "value": {{ "kind": "load_param", "name": "pubKey" }} }},
        {{ "name": "t7", "value": {{ "kind": "call", "func": "checkSig", "args": ["t5", "t6"] }} }},
        {{ "name": "t8", "value": {{ "kind": "assert", "value": "t7" }} }}
      ],
      "isPublic": true
    }}
  ]
}}"#
    )
}

/// A two-argument call, so the desynced-by-`args.len()` case is exercised at
/// an arity greater than one. `{FUNC}` = `checkSig` is the real check.
fn two_arg_anf(func: &str) -> String {
    format!(
        r#"{{
  "contractName": "TwoArg",
  "properties": [],
  "methods": [
    {{
      "name": "unlock",
      "params": [
        {{ "name": "sig", "type": "Sig" }},
        {{ "name": "pubKey", "type": "PubKey" }}
      ],
      "body": [
        {{ "name": "t0", "value": {{ "kind": "load_param", "name": "sig" }} }},
        {{ "name": "t1", "value": {{ "kind": "load_param", "name": "pubKey" }} }},
        {{ "name": "t2", "value": {{ "kind": "call", "func": "{func}", "args": ["t0", "t1"] }} }},
        {{ "name": "t3", "value": {{ "kind": "assert", "value": "t2" }} }}
      ],
      "isPublic": true
    }}
  ]
}}"#
    )
}

// ---------------------------------------------------------------------------
// The attack — defect (1): a deleted check
// ---------------------------------------------------------------------------

/// The exact end-to-end attack: take a P2PKH's IR, patch `hash160` to a name
/// the tier cannot resolve, and compile through `--ir`. The compiler must
/// refuse and name the function, not hand back a contract whose key binding
/// has been replaced by `OP_0 OP_0 OP_EQUALVERIFY`.
#[test]
fn p2pkh_with_an_unresolvable_builtin_is_refused_by_name() {
    let program =
        load_ir_from_str(&p2pkh_anf("mysteryFn")).expect("fixture ANF should deserialize");

    let result = lower_to_stack(&program);

    let err = match result {
        Ok(methods) => panic!(
            "lower_to_stack ACCEPTED a call to an unresolvable function and \
             silently compiled the key-hash check away. Emitted ops: {:?}",
            methods.iter().map(|m| &m.ops).collect::<Vec<_>>()
        ),
        Err(e) => e,
    };

    assert!(
        err.contains("mysteryFn"),
        "the diagnostic must name the unresolvable function so the author can \
         find it; got: {err}"
    );
}

/// Same attack one level up, through the public `--ir` entry point the CLI
/// uses, asserting on the artifact the attacker was after. `76000088ac` is
/// the byte string the old placeholder produced.
#[test]
fn ir_entry_point_never_emits_the_zeroed_p2pkh_script() {
    let result = runar_compiler_rust::compile_from_ir_str(&p2pkh_anf("mysteryFn"));

    match result {
        Ok(artifact) => panic!(
            "compile_from_ir_str returned an artifact for an unresolvable \
             builtin: script={} asm={}",
            artifact.script, artifact.asm
        ),
        Err(e) => assert!(
            e.contains("mysteryFn"),
            "the diagnostic must name the unresolvable function; got: {e}"
        ),
    }
}

// ---------------------------------------------------------------------------
// Defect (2): the stack-model desync, covered by elimination
// ---------------------------------------------------------------------------

/// A two-argument unresolvable call is the arity-2 form of the desync: the
/// old tail popped two model entries while leaving two values on the real
/// stack. Refusing before the placeholder push means no `StackMethod` is
/// produced at all, so there is no lowering left that could carry the skew.
#[test]
fn unresolvable_two_arg_call_is_refused_so_no_desynced_method_is_produced() {
    let program =
        load_ir_from_str(&two_arg_anf("mysteryTwoArg")).expect("fixture ANF should deserialize");

    let result = lower_to_stack(&program);

    match result {
        Ok(methods) => panic!(
            "a two-argument unresolvable call produced a method whose stack \
             model is short by 2: {:?}",
            methods.iter().map(|m| &m.ops).collect::<Vec<_>>()
        ),
        Err(e) => assert!(
            e.contains("mysteryTwoArg"),
            "the diagnostic must name the unresolvable function; got: {e}"
        ),
    }
}

// ---------------------------------------------------------------------------
// Positive controls — the fix must not be "refuse everything"
// ---------------------------------------------------------------------------

/// The real P2PKH still compiles to its golden bytes: `hash160` resolves, its
/// single argument is genuinely consumed by `OP_HASH160`, and the model stays
/// in step through the following `OP_EQUALVERIFY` / `OP_CHECKSIG`.
#[test]
fn control_real_p2pkh_still_compiles_to_its_golden_script() {
    let artifact = runar_compiler_rust::compile_from_ir_str(&p2pkh_anf("hash160"))
        .expect("the real P2PKH must still compile");

    assert_eq!(artifact.script, "76a90088ac", "asm was: {}", artifact.asm);
    assert_eq!(
        artifact.asm,
        "OP_DUP OP_HASH160 OP_0 OP_EQUALVERIFY OP_CHECKSIG"
    );
}

/// A known two-argument builtin still lowers, proving the refusal is scoped
/// to names `builtin_opcodes` cannot resolve rather than to arity.
#[test]
fn control_known_two_arg_builtin_still_lowers_and_consumes_both_args() {
    let artifact = runar_compiler_rust::compile_from_ir_str(&two_arg_anf("checkSig"))
        .expect("checkSig must still compile");

    assert!(
        artifact.asm.contains("OP_CHECKSIG"),
        "asm was: {}",
        artifact.asm
    );
    assert!(
        !artifact.asm.contains("OP_0 OP_0"),
        "no placeholder zeroes should appear; asm was: {}",
        artifact.asm
    );
}
