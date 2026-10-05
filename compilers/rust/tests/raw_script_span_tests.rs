//! F-152 — `rawScriptSpans` artifact-surface coverage for the Rust compiler.
//!
//! Before this file, `compilers/rust/tests/*.rs` had zero tests exercising
//! `RunarArtifact.raw_script_spans` end-to-end through
//! `compile_from_source_str` (the only prior coverage was a hand-built,
//! hostile-IR unit test inside `src/codegen/emit.rs`, which never goes
//! through the frontend parser at all).
//!
//! These tests pin the Rust compiler's `rawScriptSpans` output against the
//! TypeScript reference compiler for the same source. Three fixtures:
//!
//!   1. `examples/rust/asm-raw-script/Anyone.runar.rs` — the checked-in,
//!      conformance-golden-backed fixture (`conformance/tests/asm-raw-script`,
//!      no `"compilers"` allowlist, so all 7 tiers must be byte-identical on
//!      it). Exercises the Rust DSL's own `asm(body, in_arity, out_arity)`
//!      surface syntax.
//!   2-6. Literal `.runar.ts` source strings copied verbatim from
//!      `packages/runar-compiler/src/__tests__/raw-script-spans.test.ts`
//!      (the TS reference's own emit-side tests for this field), fed through
//!      the Rust compiler's TS-surface parser (frontend parity: every tier
//!      parses `.runar.ts`). Each asserted value below is the literal value
//!      that TS test asserts for the identical source.
//!
//! What these tests prove: the Rust emitter records `rawScriptSpans` entries
//! with the right offset/length/inArity/outArity for single spans, multiple
//! consecutive spans, non-default arities, and multi-byte bodies, and omits
//! the field for contracts with no `asm()` call — matching the TS reference
//! byte-for-byte on the field's *values* (not just "some span exists").
//!
//! What these tests do NOT prove: that `rawScriptSpans` is correct for every
//! possible asm() shape (e.g. the array-of-opcodes body form, or asm() inside
//! a branch/loop) — only the shapes the TS reference itself pins. They also
//! don't prove on-chain behavior; `rawScriptSpans` is off-chain debug/analyzer
//! metadata, never consulted by the VM.

use runar_compiler_rust::compile_from_source_str;
use std::path::PathBuf;

fn anyone_fixture_source() -> String {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("..");
    p.push("..");
    p.push("examples");
    p.push("rust");
    p.push("asm-raw-script");
    p.push("Anyone.runar.rs");
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read fixture {}: {}", p.display(), e))
}

// ---------------------------------------------------------------------------
// 1. Conformance-golden-backed fixture, native Rust DSL surface.
// ---------------------------------------------------------------------------

#[test]
fn anyone_fixture_records_one_span_matching_the_conformance_golden() {
    let src = anyone_fixture_source();
    let artifact = compile_from_source_str(&src, Some("Anyone.runar.rs"))
        .expect("Anyone.runar.rs fixture must compile");

    // conformance/tests/asm-raw-script/expected-script.hex is "51" (OP_1) —
    // no allowlist, so every tier (including Rust) must match it exactly.
    assert_eq!(artifact.script, "51", "script must equal the conformance golden");

    assert_eq!(
        artifact.raw_script_spans.len(),
        1,
        "expected exactly 1 RawScriptSpan, got {:?}",
        artifact.raw_script_spans
    );
    let span = &artifact.raw_script_spans[0];
    assert_eq!(span.offset, 0, "span offset");
    assert_eq!(span.length, 1, "span length");
    assert_eq!(span.in_arity, 0, "span in_arity");
    assert_eq!(span.out_arity, 1, "span out_arity");
}

// ---------------------------------------------------------------------------
// 2-6. TS-surface literal sources, pinned against
//      packages/runar-compiler/src/__tests__/raw-script-spans.test.ts.
// ---------------------------------------------------------------------------

#[test]
fn ts_surface_records_a_single_span_for_a_one_call_asm_contract() {
    // Mirrors raw-script-spans.test.ts > 'records a single span for a
    // one-call asm() contract'.
    let source = r#"
        import { UnsafeSmartContract, asm } from 'runar-lang';

        class WithAsm extends UnsafeSmartContract {
          constructor() {
            super();
          }

          public unlock() {
            asm({ body: '51', in_arity: 0, out_arity: 1 });
          }
        }
    "#;
    let artifact = compile_from_source_str(source, Some("WithAsm.runar.ts"))
        .expect("WithAsm must compile");
    assert_eq!(artifact.raw_script_spans.len(), 1);
    let span = &artifact.raw_script_spans[0];
    assert_eq!((span.offset, span.length, span.in_arity, span.out_arity), (0, 1, 0, 1));
}

#[test]
fn ts_surface_records_consecutive_spans_with_monotonically_increasing_offsets() {
    // Mirrors raw-script-spans.test.ts > 'records consecutive spans with
    // monotonically increasing offsets'.
    let source = r#"
        import { UnsafeSmartContract, asm } from 'runar-lang';

        class WithAsm extends UnsafeSmartContract {
          constructor() {
            super();
          }

          public unlock() {
            asm({ body: '51', in_arity: 0, out_arity: 1 });
            asm({ body: '6151', in_arity: 1, out_arity: 1 });
          }
        }
    "#;
    let artifact = compile_from_source_str(source, Some("WithAsm.runar.ts"))
        .expect("WithAsm must compile");
    assert_eq!(artifact.script, "516151", "emitted hex must match TS reference");
    assert_eq!(artifact.raw_script_spans.len(), 2);
    let s0 = &artifact.raw_script_spans[0];
    let s1 = &artifact.raw_script_spans[1];
    assert_eq!((s0.offset, s0.length, s0.in_arity, s0.out_arity), (0, 1, 0, 1));
    assert_eq!((s1.offset, s1.length, s1.in_arity, s1.out_arity), (1, 2, 1, 1));
}

#[test]
fn ts_surface_carries_non_default_arities_through_to_the_artifact() {
    // Mirrors raw-script-spans.test.ts > 'carries non-default arities
    // through to the artifact'.
    let source = r#"
        import { UnsafeSmartContract, asm } from 'runar-lang';

        class WithAsm extends UnsafeSmartContract {
          constructor() {
            super();
          }

          public unlock(a: bigint, b: bigint) {
            asm({ body: '87', in_arity: 2, out_arity: 1 });
          }
        }
    "#;
    let artifact = compile_from_source_str(source, Some("WithAsm.runar.ts"))
        .expect("WithAsm must compile");
    assert_eq!(artifact.raw_script_spans.len(), 1);
    let span = &artifact.raw_script_spans[0];
    assert_eq!((span.offset, span.length, span.in_arity, span.out_arity), (0, 1, 2, 1));
}

#[test]
fn ts_surface_omits_raw_script_spans_for_contracts_with_no_asm() {
    // Mirrors raw-script-spans.test.ts > 'omits `rawScriptSpans` entirely
    // for contracts that use no asm()'. The TS artifact field is `undefined`
    // (optional, JSON-absent); the Rust field is a plain Vec (never Option),
    // so the Rust-side invariant is "empty", and `#[serde(skip_serializing_if
    // = "Vec::is_empty")]` on `RunarArtifact.raw_script_spans` keeps the
    // serialized JSON key absent too, matching the TS wire shape.
    let source = r#"
        import { SmartContract, assert } from 'runar-lang';

        class Always extends SmartContract {
          constructor() { super(); }
          public unlock(): void {
            assert(1n === 1n);
          }
        }
    "#;
    let artifact =
        compile_from_source_str(source, Some("Always.runar.ts")).expect("Always must compile");
    assert!(
        artifact.raw_script_spans.is_empty(),
        "expected no raw script spans, got {:?}",
        artifact.raw_script_spans
    );
    let json = serde_json::to_string(&artifact).expect("serialize artifact");
    assert!(
        !json.contains("rawScriptSpans"),
        "rawScriptSpans key must be absent from the serialized artifact when empty"
    );
}

#[test]
fn ts_surface_records_a_span_at_the_correct_offset_inside_a_multi_byte_body() {
    // Mirrors raw-script-spans.test.ts > 'records a span at the correct
    // offset inside a multi-byte body'.
    let source = r#"
        import { UnsafeSmartContract, asm } from 'runar-lang';

        class WithAsm extends UnsafeSmartContract {
          constructor() {
            super();
          }

          public unlock() {
            asm({ body: '76a90051', in_arity: 0, out_arity: 1 });
          }
        }
    "#;
    let artifact = compile_from_source_str(source, Some("WithAsm.runar.ts"))
        .expect("WithAsm must compile");
    assert_eq!(artifact.script, "76a90051");
    assert_eq!(artifact.raw_script_spans.len(), 1);
    let span = &artifact.raw_script_spans[0];
    assert_eq!((span.offset, span.length, span.in_arity, span.out_arity), (0, 4, 0, 1));
}
