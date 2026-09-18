//! Port of the TypeScript reference test
//! `packages/runar-compiler/src/__tests__/n098-bytestring-satoshis.test.ts`.
//!
//! N-098 — a ByteString in the SATOSHIS position of an output intrinsic.
//!
//! This tier ACCEPTED all three shapes. It was not a missing diagnostic: the
//! ByteString was lowered into the satoshis slot with NO conversion, and the
//! emitted script was byte-identical to the same contract written with
//! `blob: bigint` — 1358 hexchars, same digest, in all six accepting tiers.
//!
//! `lower_add_output` prepends the satoshis operand as `OP_8 OP_NUM2BIN`, so
//! the covenant commits to whatever those bytes decode to as a script number.
//! Executed on the real `@bsv/sdk` Spend engine with `blob = 0x2a`, a
//! 42-satoshi continuation VALIDATES and the 1000-satoshi one the author funded
//! is REJECTED. Bigger blobs fail shut rather than safe: `0xcafebabefeed0001`
//! demands 7.2e16 satoshis and a 20-byte hash aborts the script at
//! `OP_NUM2BIN`, leaving the UTXO permanently unspendable.
//!
//! The rule ported here is the TypeScript reference's, wording included
//! (`check_call_expr`'s addOutput / addRawOutput / addDataOutput arms). Only
//! the FIRST argument is checked. TS additionally checks arity, the state-value
//! types and the `scriptBytes` argument; none of those are ported here and none
//! of them are this finding.
//!
//! The ACCEPT block carries the real risk in a change like this. `<unknown>`
//! must stay accepted: a private helper's declared return type is discarded at
//! parse time in every tier, so `this.sats()` infers as `<unknown>`, and TS has
//! always escaped it here.

use runar_compiler_rust::{compile_from_source_str_with_options, CompileOptions};

const HEAD: &str = r#"import { StatefulSmartContract, ByteString, assert } from 'runar-lang';

class C extends StatefulSmartContract {
  count: bigint;
  readonly base: bigint;
  readonly blob: ByteString;

  constructor(count: bigint, base: bigint, blob: ByteString) {
    super(count, base, blob);
    this.count = count;
    this.base = base;
    this.blob = blob;
  }

  private sats(): bigint { return this.base; }

"#;

// --- REJECT ----------------------------------------------------------------

const ADD_OUTPUT_BODY: &str = r#"  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(this.blob, this.count);
  }
}
"#;

const ADD_RAW_OUTPUT_BODY: &str = r#"  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(this.blob, this.blob);
  }
}
"#;

const ADD_DATA_OUTPUT_BODY: &str = r#"  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addDataOutput(this.blob, this.blob);
  }
}
"#;

// --- ACCEPT (over-rejection guards) ----------------------------------------

const LITERAL_SATS_BODY: &str = r#"  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
  }
}
"#;

const PARAM_SATS_BODY: &str = r#"  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(n, this.count);
  }
}
"#;

const PROPERTY_SATS_BODY: &str = r#"  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(this.base, this.count);
  }
}
"#;

/// A private helper's declared return type is discarded at parse time in EVERY
/// tier, so this infers as `<unknown>`. It must stay ACCEPTED.
const HELPER_SATS_BODY: &str = r#"  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(this.sats(), this.count);
  }
}
"#;

fn contract(body: &str) -> String {
    format!("{}{}", HEAD, body)
}

fn compile(source: &str) -> Result<String, String> {
    let opts = CompileOptions::default();
    compile_from_source_str_with_options(source, Some("C.runar.ts"), &opts)
        .map(|artifact| artifact.script)
}

fn require_diagnostic(body: &str, want: &str) {
    match compile(&contract(body)) {
        Ok(hex) => panic!(
            "expected a diagnostic containing {:?}; the contract COMPILED to {} hexchars",
            want,
            hex.len()
        ),
        Err(e) => assert!(
            e.contains(want),
            "expected a diagnostic containing {:?}; got:\n{}",
            want,
            e
        ),
    }
}

fn compile_ok(body: &str) -> String {
    match compile(&contract(body)) {
        Ok(hex) => hex,
        Err(e) => panic!("expected this contract to compile; got:\n{}", e),
    }
}

#[test]
fn add_output_rejects_bytestring_satoshis() {
    require_diagnostic(
        ADD_OUTPUT_BODY,
        "addOutput() first argument (satoshis) must be bigint, got 'ByteString'",
    );
}

#[test]
fn add_raw_output_rejects_bytestring_satoshis() {
    require_diagnostic(
        ADD_RAW_OUTPUT_BODY,
        "addRawOutput() first argument (satoshis) must be bigint, got 'ByteString'",
    );
}

#[test]
fn add_data_output_rejects_bytestring_satoshis() {
    require_diagnostic(
        ADD_DATA_OUTPUT_BODY,
        "addDataOutput() first argument (satoshis) must be bigint, got 'ByteString'",
    );
}

#[test]
fn accepted_satoshis_positions() {
    for (name, body) in [
        ("bigint literal", LITERAL_SATS_BODY),
        ("bigint method parameter", PARAM_SATS_BODY),
        ("bigint contract property", PROPERTY_SATS_BODY),
        ("private helper call, inferred as <unknown>", HELPER_SATS_BODY),
    ] {
        let hex = compile_ok(body);
        assert!(!hex.is_empty(), "{name} compiled to an empty script");
    }
}

/// Non-vacuity: "it compiled" would also hold for a tier that discarded the
/// satoshis operand entirely. A literal and a runtime parameter must lower to
/// DIFFERENT scripts. Every tier's own N-098 test makes this same assertion.
#[test]
fn satoshis_operand_reaches_codegen() {
    let lit = compile_ok(LITERAL_SATS_BODY);
    let param = compile_ok(PARAM_SATS_BODY);
    assert_ne!(
        lit, param,
        "literal and parameter satoshis produced the same script — the operand is being dropped"
    );
    assert!(
        lit.contains("02e803"), // PUSH(2) 0xe8 0x03 == 1000
        "literal 1000n does not appear in the emitted script"
    );
}
