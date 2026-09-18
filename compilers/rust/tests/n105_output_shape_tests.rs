//! N-105 (2/2) — the rest of TypeScript's output-intrinsic CONTRACT: the
//! StatefulSmartContract gate, the arity of all three intrinsics, and the types
//! of addOutput's state values.
//!
//! N-098 ported the satoshis check and N-105 (1/2) the scriptBytes check. These
//! three are the remainder, and each was a hole with an executed consequence in
//! this tier:
//!
//! ```text
//! this.addOutput(1000n)                  1352 hexchars — the state value is
//!   with one mutable property            simply MISSING from the continuation;
//!                                        the correct call emits 1362.
//! this.addOutput(1000n, this.count, 5n)  1368 hexchars — the surplus value is
//!                                        appended to a state serialization the
//!                                        next spend deserializes by fixed
//!                                        offsets.
//! this.addOutput(1000n, this.blob)       1362 hexchars, DIFFERENT bytes — the
//!   with count: bigint                   ByteString is serialized where an
//!                                        8-byte LE number belongs.
//! this.addRawOutput(...) in a            152 hexchars — a "continuation" in a
//!   stateless SmartContract              contract that has no state.
//! ```
//!
//! All four are the same class as N-098: the compiler does not refuse, it emits
//! a covenant that commits to the wrong thing.
//!
//! Ported from the TypeScript reference, wording included.
//!
//! The ACCEPT block is where the risk is. A ByteString-typed value in a
//! PubKey-typed state slot must stay ACCEPTED: TS's `isSubtype` treats the
//! ByteString family as bidirectionally compatible.

use runar_compiler_rust::{compile_from_source_str_with_options, CompileOptions};

const HEAD: &str = r#"import { StatefulSmartContract, ByteString, PubKey, assert } from 'runar-lang';

class C extends StatefulSmartContract {
  count: bigint;
  owner: PubKey;
  readonly base: bigint;
  readonly blob: ByteString;

  constructor(count: bigint, owner: PubKey, base: bigint, blob: ByteString) {
    super(count, owner, base, blob);
    this.count = count;
    this.owner = owner;
    this.base = base;
    this.blob = blob;
  }

  private anything(): bigint { return this.base; }

"#;

const STATELESS_HEAD: &str = r#"import { SmartContract, ByteString, assert } from 'runar-lang';

class C extends SmartContract {
  readonly base: bigint;
  readonly blob: ByteString;

  constructor(base: bigint, blob: ByteString) {
    super(base, blob);
    this.base = base;
    this.blob = blob;
  }

"#;

// --- REJECT: arity ---------------------------------------------------------

const ARITY_TOO_FEW: &str = r#"  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count);
  }
}
"#;

const ARITY_TOO_MANY: &str = r#"  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count, this.owner, 5n);
  }
}
"#;

const RAW_ARITY_ONE: &str = r#"  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count, this.owner);
    this.addRawOutput(500n);
  }
}
"#;

const RAW_ARITY_THREE: &str = r#"  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count, this.owner);
    this.addRawOutput(500n, this.blob, 7n);
  }
}
"#;

const DATA_ARITY_THREE: &str = r#"  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count, this.owner);
    this.addDataOutput(500n, this.blob, 7n);
  }
}
"#;

// --- REJECT: state-value types ---------------------------------------------

const STATE_VALUE_WRONG_TYPE: &str = r#"  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.blob, this.owner);
  }
}
"#;

// --- REJECT: the StatefulSmartContract gate --------------------------------

const STATELESS_ADD_OUTPUT: &str = r#"  public m(n: bigint) {
    this.addOutput(1000n, n);
    assert(n > 0n);
  }
}
"#;

const STATELESS_ADD_RAW_OUTPUT: &str = r#"  public m(n: bigint) {
    this.addRawOutput(1000n, this.blob);
    assert(n > 0n);
  }
}
"#;

const STATELESS_ADD_DATA_OUTPUT: &str = r#"  public m(n: bigint) {
    this.addDataOutput(1000n, this.blob);
    assert(n > 0n);
  }
}
"#;

// --- ACCEPT (over-rejection guards) ----------------------------------------

const SHAPE_EXACT: &str = r#"  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.count, this.owner);
  }
}
"#;

/// A ByteString value in a PubKey state slot. TS's `isSubtype` treats the
/// ByteString family as bidirectionally compatible, so TS ACCEPTS this and
/// every tier must keep accepting it — measured before this change, all seven
/// tiers compiled it to the same script.
const SHAPE_FAMILY_WIDENING: &str = r#"  public m(n: bigint, b: ByteString) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count, b);
  }
}
"#;

/// A private helper's declared return type is discarded at parse time in every
/// tier, so this infers as `<unknown>`. TS escapes it; every port must too.
const SHAPE_UNKNOWN_STATE_VALUE: &str = r#"  public m(n: bigint, who: PubKey) {
    assert(n > 0n);
    this.count = this.count + n;
    this.owner = who;
    this.addOutput(1000n, this.anything(), this.owner);
  }
}
"#;

/// The one-mutable-property shape: the arity rule must be derived from the
/// contract, not hardcoded.
const ONE_PROP: &str = r#"import { StatefulSmartContract, ByteString, assert } from 'runar-lang';

class C extends StatefulSmartContract {
  count: bigint;
  readonly blob: ByteString;

  constructor(count: bigint, blob: ByteString) {
    super(count, blob);
    this.count = count;
    this.blob = blob;
  }

  public m(n: bigint) {
    assert(n > 0n);
    this.count = this.count + n;
    this.addOutput(1000n, this.count);
    this.addRawOutput(500n, this.blob);
  }
}
"#;

/// A FixedArray state property. `expand_fixed_arrays` runs AFTER the
/// typechecker in this tier and splits `board` into three scalar siblings, so
/// the only call shape that lowers is the EXPANDED one below — which the arity
/// rule, counting the two DECLARED mutable properties, would reject. This is
/// the contract from
/// `compilers/python/tests/test_r025_expand_fixed_arrays_field_preservation.py`,
/// checked into this repo and compiled by all six non-TS tiers; the TypeScript
/// reference rejects it ("expects 3 argument(s) ... got 5"), which is a defect
/// in the reference rule, not in this source.
const FIXED_ARRAY_STATE: &str = r#"import { StatefulSmartContract, assert } from 'runar-lang';
import type { FixedArray } from 'runar-lang';

class Boardy extends StatefulSmartContract {
  board: FixedArray<bigint, 3> = [0n, 0n, 0n];
  n: bigint;
  constructor(n: bigint) { super(n); this.n = n; }
  public bump(): void { this.addOutput(1000n, this.board[0], this.board[1], this.board[2], this.n); }
}
"#;

fn compile(source: &str) -> Result<String, String> {
    let opts = CompileOptions::default();
    compile_from_source_str_with_options(source, Some("C.runar.ts"), &opts)
        .map(|artifact| artifact.script)
}

fn require_diagnostic(source: &str, want: &str) {
    match compile(source) {
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

fn compile_ok(source: &str) -> String {
    match compile(source) {
        Ok(hex) => hex,
        Err(e) => panic!("expected this contract to compile; got:\n{}", e),
    }
}

fn stateful(body: &str) -> String {
    format!("{}{}", HEAD, body)
}

fn stateless(body: &str) -> String {
    format!("{}{}", STATELESS_HEAD, body)
}

#[test]
fn add_output_arity() {
    require_diagnostic(
        &stateful(ARITY_TOO_FEW),
        "addOutput() expects 3 argument(s): satoshis + 2 state value(s), got 2",
    );
    require_diagnostic(
        &stateful(ARITY_TOO_MANY),
        "addOutput() expects 3 argument(s): satoshis + 2 state value(s), got 4",
    );
}

#[test]
fn raw_and_data_output_arity() {
    require_diagnostic(
        &stateful(RAW_ARITY_ONE),
        "addRawOutput() expects 2 arguments (satoshis, scriptBytes), got 1",
    );
    require_diagnostic(
        &stateful(RAW_ARITY_THREE),
        "addRawOutput() expects 2 arguments (satoshis, scriptBytes), got 3",
    );
    require_diagnostic(
        &stateful(DATA_ARITY_THREE),
        "addDataOutput() expects 2 arguments (satoshis, scriptBytes), got 3",
    );
}

#[test]
fn add_output_state_value_types() {
    require_diagnostic(
        &stateful(STATE_VALUE_WRONG_TYPE),
        "addOutput() argument 2 (count) must be 'bigint', got 'ByteString'",
    );
}

#[test]
fn output_intrinsics_are_stateful_only() {
    require_diagnostic(
        &stateless(STATELESS_ADD_OUTPUT),
        "addOutput() is only available in StatefulSmartContract",
    );
    require_diagnostic(
        &stateless(STATELESS_ADD_RAW_OUTPUT),
        "addRawOutput() is only available in StatefulSmartContract",
    );
    require_diagnostic(
        &stateless(STATELESS_ADD_DATA_OUTPUT),
        "addDataOutput() is only available in StatefulSmartContract",
    );
}

#[test]
fn accepted_output_shapes() {
    for (name, source) in [
        ("exact arity and exact types", stateful(SHAPE_EXACT)),
        (
            "ByteString value in a PubKey state slot",
            stateful(SHAPE_FAMILY_WIDENING),
        ),
        (
            "private helper call, inferred as <unknown>",
            stateful(SHAPE_UNKNOWN_STATE_VALUE),
        ),
    ] {
        assert!(
            !compile_ok(&source).is_empty(),
            "{name} compiled to an empty script"
        );
    }
}

/// Non-vacuity: the arity rule must be derived from the contract's mutable
/// properties, not hardcoded. A two-mutable-property contract wants three
/// arguments; a one-mutable-property contract wants two, and both must compile.
#[test]
fn arity_is_derived_from_mutable_properties() {
    assert!(!compile_ok(ONE_PROP).is_empty());
    assert!(!compile_ok(&stateful(SHAPE_EXACT)).is_empty());
}

/// The carve-out above, pinned: a FixedArray-state contract must stay
/// compilable.
#[test]
fn fixed_array_state_is_out_of_scope() {
    assert!(!compile_ok(FIXED_ARRAY_STATE).is_empty());
}
