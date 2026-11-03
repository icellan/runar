//! F-152 — `codeSeparatorIndex` / `codeSeparatorIndices` artifact-surface
//! coverage for the Rust compiler.
//!
//! Before this file, `compilers/rust/tests/*.rs` had no test that compiled a
//! source contract end-to-end and asserted on `RunarArtifact.code_separator_index`
//! / `code_separator_indices` (the only prior matches were incidental: a string
//! appearing inside an unrelated test's comment/fixture).
//!
//! `OP_CODESEPARATOR` placement (`compilers/rust/src/codegen/stack.rs`,
//! `lower_check_preimage` / R-010) is a contract-level decision:
//!   - if any public method (or the constructor) authenticates a `_codePart`
//!     witness, ONE separator is emitted at offset 1 of the locking script
//!     (`emit`, `compilers/rust/src/codegen/emit.rs`);
//!   - otherwise, every manual `checkPreimage()` call gets its OWN separator
//!     at its method's entry (the pre-R-010 layout).
//! In both cases `code_separator_index` records the LAST separator's byte
//! offset and `code_separator_indices` records every separator's offset, in
//! emission order (`compilers/rust/src/codegen/emit.rs::emit_opcode`, mirrors
//! TypeScript's `EmitContext.emitOpcode` in `passes/06-emit.ts`).
//!
//! All three expected-value sets below were captured by compiling the exact
//! same `.runar.ts` source through the TypeScript reference compiler
//! (`packages/runar-compiler/dist/index.js`, `compile(source, { fileName,
//! disableConstantFolding: true })` — fold-OFF, matching the checked-in
//! conformance goldens) at test-authoring time (2026-10-05). The stateful
//! `Counter` source and its fold-OFF hex are the same fixture pinned byte-for-
//! byte in `packages/runar-compiler/src/__tests__/06-emit.test.ts` ("canonical
//! stateful Counter ... emits exact bytes").
//!
//! What these tests prove: the Rust emitter computes the SAME
//! `codeSeparatorIndex` / `codeSeparatorIndices` values as the TS reference
//! for (a) the single-separator "script-level" layout (stateful contract with
//! `_codePart`), (b) the multi-separator "per-method" layout (two manual
//! `checkPreimage()` calls, no `_codePart`), and (c) the omitted-field case
//! (no `checkPreimage` at all).
//!
//! What these tests do NOT prove: coverage of every topology that can produce
//! 3+ separators, separators inside branches/loops, or on-chain behavior —
//! these fields are off-chain SDK/debug metadata, never read by the VM.

use runar_compiler_rust::{compile_from_source_str_with_options, CompileOptions};

fn compile_fold_off(src: &str, file: &str) -> runar_compiler_rust::artifact::RunarArtifact {
    let opts = CompileOptions { disable_constant_folding: true, ..CompileOptions::default() };
    compile_from_source_str_with_options(src, Some(file), &opts)
        .unwrap_or_else(|e| panic!("{file} failed to compile: {e}"))
}

// ---------------------------------------------------------------------------
// (a) Script-level layout: one separator, shared by index and indices.
// ---------------------------------------------------------------------------

const COUNTER_SOURCE: &str = r#"
import { StatefulSmartContract, assert } from 'runar-lang';
class Counter extends StatefulSmartContract {
  count: bigint;
  constructor(count: bigint) { super(count); this.count = count; }
  public increment(): void {
    this.count = this.count + 1n;
    this.addOutput(1000n, this.count);
  }
}
"#;

/// The fold-OFF hex for `COUNTER_SOURCE`, captured from the TS reference
/// compiler. Byte-identical to the golden pinned in 06-emit.test.ts's
/// "canonical stateful Counter" case (that test asserts the same hex split
/// across string-literal concatenations; this is the same value, unsplit).
const COUNTER_SCRIPT_HEX: &str = "61ab7676aa517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f517f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e01007e8100011f80517e9321414136d08c5ed2bf3ba048afe6dcaebafeffffffffffffffffffffffffffffff007d97785296789f527952798d9495937776927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f76927f7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e7c7e827c7e23022079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798027c7e827c7e01307c7e01417e2102b405d7f0322a89d0f9f3a98e6f938fdc1c969a8d1382a2bf66a71ae74a1e83b0ad7601687f77820134947f75517f7c01007e817602fd009f6375677602fe009c6375547f77677602ff009c6375587f776775527f7768686855798252947b7c7f82599d517f75016a880261ab7c7e8869768254947f7701007e8101419d7601687f7782012c947f758258947f758258947f7781768b7702e803785679016a7e7c58807e827602fd009f635280517f756776030000019f635380527f7501fd7c7e67760500000000019f635580547f7501fe7c7e675980587f7501ff7c7e6868687c7e7c58807c7e547a547a00787c9c9163041976a9147b7e0288ac7e7c58807c7e67007b7577687eaa7b820128947f7701207f75877777";

#[test]
fn stateful_counter_gets_one_script_level_separator_matching_ts_reference() {
    let artifact = compile_fold_off(COUNTER_SOURCE, "Counter.runar.ts");
    assert_eq!(artifact.script, COUNTER_SCRIPT_HEX, "fold-OFF hex must match the TS reference");
    assert_eq!(
        artifact.code_separator_index,
        Some(1),
        "codeSeparatorIndex must be 1 (OP_NOP at 0, OP_CODESEPARATOR at 1)"
    );
    assert_eq!(
        artifact.code_separator_indices,
        Some(vec![1]),
        "codeSeparatorIndices must contain exactly the one script-level separator"
    );
}

// ---------------------------------------------------------------------------
// (b) Per-method (pre-R-010) layout: two separators, two distinct offsets.
// ---------------------------------------------------------------------------

const TWO_GATE_SOURCE: &str = r#"
import { SmartContract, assert, checkPreimage } from 'runar-lang';
import type { SigHashPreimage } from 'runar-lang';
class TwoGate extends SmartContract {
  constructor() { super(); }
  public pathA(preimage: SigHashPreimage) {
    assert(checkPreimage(preimage));
  }
  public pathB(preimage: SigHashPreimage) {
    assert(checkPreimage(preimage));
  }
}
"#;

#[test]
fn two_manual_checkpreimage_calls_get_two_distinct_per_method_separators() {
    // No method ever touches `_codePart`, so this takes the pre-R-010
    // per-method branch in `lower_check_preimage`: each of the two public
    // methods gets its own OP_CODESEPARATOR at its own entry.
    let artifact = compile_fold_off(TWO_GATE_SOURCE, "TwoGate.runar.ts");
    assert_eq!(
        artifact.code_separator_indices,
        Some(vec![5, 437]),
        "expected two per-method separators at the TS-reference offsets"
    );
    assert_eq!(
        artifact.code_separator_index,
        Some(437),
        "codeSeparatorIndex must record the LAST separator emitted (overwrite, not min/max)"
    );
}

// ---------------------------------------------------------------------------
// (c) No `checkPreimage` anywhere: both fields absent, not empty/zero.
// ---------------------------------------------------------------------------

const P2PKH_SOURCE: &str = r#"
import { SmartContract, assert, PubKey, Sig, Addr, hash160, checkSig } from 'runar-lang';
class P2PKH extends SmartContract {
  readonly pubKeyHash: Addr;
  constructor(pubKeyHash: Addr) { super(pubKeyHash); this.pubKeyHash = pubKeyHash; }
  public unlock(sig: Sig, pubKey: PubKey) {
    assert(hash160(pubKey) === this.pubKeyHash);
    assert(checkSig(sig, pubKey));
  }
}
"#;

#[test]
fn contract_with_no_checkpreimage_omits_both_fields() {
    let artifact = compile_fold_off(P2PKH_SOURCE, "P2PKH.runar.ts");
    assert_eq!(artifact.script, "76a90088ac");
    assert_eq!(artifact.code_separator_index, None, "no checkPreimage => no index");
    assert_eq!(artifact.code_separator_indices, None, "no checkPreimage => no indices");

    let json = serde_json::to_string(&artifact).expect("serialize artifact");
    assert!(!json.contains("codeSeparatorIndex"), "key must be absent when None");
}
