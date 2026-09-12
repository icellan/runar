//! N-105 (1/2) — a NUMBER in the scriptBytes position of addRawOutput /
//! addDataOutput.
//!
//! Same shape as N-098, one argument slot over, and the slot is the created
//! output's LOCKING SCRIPT.
//!
//! This tier ACCEPTED `this.addRawOutput(1000n, n)` with `n: bigint`, and the
//! emitted script was byte-identical to the same contract written with
//! `n: ByteString` — measured, same digest. The operand is not converted:
//! whatever sits in that slot is spliced into the output serialization as the
//! output's script.
//!
//! `lower_add_raw_output` takes OP_SIZE of the operand, varint-prefixes it and
//! concatenates it after the 8-byte amount. A script NUMBER on the stack is its
//! minimal little-endian encoding, so the covenant commits to an output whose
//! locking script IS those bytes. Executed on the real `@bsv/sdk` Spend engine
//! against the exact 55-opcode window all six tiers emit:
//!
//! ```text
//! n=0     -> scriptLen 0   locking script (empty)     — anyone-can-spend
//! n=81    -> scriptLen 1   0x51 = OP_1                — anyone-can-spend
//! n=118   -> scriptLen 1   0x76 = OP_DUP              — anyone-can-spend
//! n=1000  -> scriptLen 2   0xe8 0x03, 0xe8 invalid    — unspendable
//! ```
//!
//! N-098's failure mode was a wrong amount or a frozen UTXO. This one can hand
//! the whole output to anybody who sees it, which is why it is a gate.
//!
//! Ported from the TypeScript reference, wording included. `<unknown>` stays
//! ACCEPTED exactly as TS has it.

use runar_compiler_rust::{compile_from_source_str_with_options, CompileOptions};

const HEAD: &str = r#"import { StatefulSmartContract, ByteString, Ripemd160, assert } from 'runar-lang';

class C extends StatefulSmartContract {
  count: bigint;
  readonly base: bigint;
  readonly flag: boolean;
  readonly blob: ByteString;
  readonly pkh: Ripemd160;

  constructor(count: bigint, base: bigint, flag: boolean, blob: ByteString, pkh: Ripemd160) {
    super(count, base, flag, blob, pkh);
    this.count = count;
    this.base = base;
    this.flag = flag;
    this.blob = blob;
    this.pkh = pkh;
  }

  private bytes(): ByteString { return this.blob; }

"#;

// --- REJECT ----------------------------------------------------------------

const RAW_BIGINT_SCRIPT: &str = r#"  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.base);
  }
}
"#;

const DATA_BIGINT_SCRIPT: &str = r#"  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addDataOutput(500n, this.base);
  }
}
"#;

const RAW_BOOLEAN_SCRIPT: &str = r#"  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.flag);
  }
}
"#;

// --- ACCEPT (over-rejection guards) ----------------------------------------

const RAW_BYTESTRING_SCRIPT: &str = r#"  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.blob);
  }
}
"#;

const RAW_STATE_SCRIPT: &str = r#"  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.getStateScript());
  }
}
"#;

/// A ByteString SUBTYPE. TS's rule is `is_subtype(script_type, "ByteString")`,
/// not equality, so Ripemd160 must keep compiling.
const RAW_SUBTYPE_SCRIPT: &str = r#"  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.pkh);
  }
}
"#;

/// A private helper's declared return type is discarded at parse time in every
/// tier, so this infers as `<unknown>`. TS escapes it; every port must too.
const RAW_HELPER_SCRIPT: &str = r#"  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.bytes());
  }
}
"#;

const DATA_BYTESTRING_SCRIPT: &str = r#"  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addDataOutput(500n, this.blob);
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
fn add_raw_output_rejects_bigint_script_bytes() {
    require_diagnostic(
        RAW_BIGINT_SCRIPT,
        "addRawOutput() second argument (scriptBytes) must be ByteString, got 'bigint'",
    );
}

#[test]
fn add_data_output_rejects_bigint_script_bytes() {
    require_diagnostic(
        DATA_BIGINT_SCRIPT,
        "addDataOutput() second argument (scriptBytes) must be ByteString, got 'bigint'",
    );
}

#[test]
fn add_raw_output_rejects_boolean_script_bytes() {
    require_diagnostic(
        RAW_BOOLEAN_SCRIPT,
        "addRawOutput() second argument (scriptBytes) must be ByteString, got 'boolean'",
    );
}

#[test]
fn accepted_script_bytes_positions() {
    for (name, body) in [
        ("ByteString property", RAW_BYTESTRING_SCRIPT),
        ("getStateScript()", RAW_STATE_SCRIPT),
        ("ByteString subtype (Ripemd160)", RAW_SUBTYPE_SCRIPT),
        ("private helper call, inferred as <unknown>", RAW_HELPER_SCRIPT),
        ("addDataOutput with a ByteString property", DATA_BYTESTRING_SCRIPT),
    ] {
        let hex = compile_ok(body);
        assert!(!hex.is_empty(), "{name} compiled to an empty script");
    }
}

/// Non-vacuity: "it compiled" would also hold for a tier that discarded the
/// scriptBytes operand. Two DIFFERENT ByteString operands must lower to
/// different scripts.
#[test]
fn script_bytes_operand_reaches_codegen() {
    let a = compile_ok(RAW_BYTESTRING_SCRIPT);
    let b = compile_ok(RAW_STATE_SCRIPT);
    assert_ne!(
        a, b,
        "two different scriptBytes operands produced the same script — the operand is being dropped"
    );
}

/// The reason this was invisible: the rejected source lowered EXACTLY like a
/// correct one. The rule must remove the bad program and nothing else.
#[test]
fn bytestring_twin_still_compiles() {
    assert!(
        compile(&contract(RAW_BIGINT_SCRIPT)).is_err(),
        "the bigint-scriptBytes source was not rejected"
    );
    assert!(
        compile(&contract(RAW_BYTESTRING_SCRIPT)).is_ok(),
        "the ByteString twin must still compile"
    );
}
