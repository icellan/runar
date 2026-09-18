//! R-015 (CL-BUG-138) — a mutable `Sig` / `SigHashPreimage` state field must be
//! read from the CURRENT on-chain state, not from the deploy-time constructor
//! placeholder.
//!
//! `codegen/stack.rs` kept two lists of "which state-field types are stored
//! push-data-framed and therefore variable-length":
//!
//!   * `is_variable_length_state_type` / the `lower_deserialize_state` size
//!     table / `fixed_state_section_length` — all three say
//!     `ByteString | Sig | SigHashPreimage`;
//!   * the `var_len_props` set inside `compute_uses_code_part` — said
//!     `ByteString` alone.
//!
//! For a terminal method (no continuation output) that reads a mutable `Sig`
//! field the second list won: `uses_code_part` stayed false, so `_codePart` was
//! never pushed, `lower_deserialize_state` took its `!self.sm.has("_codePart")`
//! shortcut and simply `OP_DROP`ped the extracted scriptCode without pushing a
//! single mutable property onto the stack map. Every later `load_prop` then
//! missed and fell through to `StackOp::Placeholder` — the constructor slot the
//! SDK splices at DEPLOY time. A rotating key or signature field could be
//! updated on-chain for ever without the script noticing.
//!
//! The deploy-time writer settles which list is right: the SDK's
//! `encodeStateValue` (packages/runar-sdk/src/state.ts) frames every type that
//! is not in its fixed-size list — `Sig` and `SigHashPreimage` included — with
//! a push-data prefix. They ARE variable-length state, so `var_len_props` was
//! the outlier.
//!
//! The `ByteString` control below already worked before the fix, so these tests
//! discriminate between the two paths rather than asserting something that
//! holds for every contract.

use runar_compiler_rust::codegen::stack::{lower_to_stack, StackMethod, StackOp};
use runar_compiler_rust::frontend::{anf_lower::lower_to_anf, parser::parse_source};

/// Control — mutable `ByteString` field, already on the working path.
const BYTESTRING_CONTROL: &str = r#"import { StatefulSmartContract, assert, len } from 'runar-lang';
import type { ByteString } from 'runar-lang';
class R015ByteStringState extends StatefulSmartContract {
  stored: ByteString;
  constructor(stored: ByteString) { super(stored); this.stored = stored; }
  public check(expected: bigint): void { assert(len(this.stored) === expected); }
}"#;

/// Bug case — mutable `Sig` field.
const SIG_STATE: &str = r#"import { StatefulSmartContract, assert, len } from 'runar-lang';
import type { Sig } from 'runar-lang';
class R015SigState extends StatefulSmartContract {
  stored: Sig;
  constructor(stored: Sig) { super(stored); this.stored = stored; }
  public check(expected: bigint): void { assert(len(this.stored) === expected); }
}"#;

/// Bug case — mutable `SigHashPreimage` field.
const PREIMAGE_STATE: &str = r#"import { StatefulSmartContract, assert, len } from 'runar-lang';
import type { SigHashPreimage } from 'runar-lang';
class R015PreimageState extends StatefulSmartContract {
  stored: SigHashPreimage;
  constructor(stored: SigHashPreimage) { super(stored); this.stored = stored; }
  public check(expected: bigint): void { assert(len(this.stored) === expected); }
}"#;

fn lower_check(src: &str) -> StackMethod {
    let parsed = parse_source(src, Some("R015.runar.ts"));
    assert!(parsed.errors.is_empty(), "parse errors: {:?}", parsed.errors);
    let contract = parsed.contract.expect("parse produced no contract");
    let anf = lower_to_anf(&contract);
    let methods = lower_to_stack(&anf).expect("stack lowering failed");
    methods
        .into_iter()
        .find(|m| m.name == "check")
        .expect("no `check` method in the lowered program")
}

/// Every constructor-slot placeholder emitted for `prop`.
fn placeholders_for(method: &StackMethod, prop: &str) -> usize {
    method
        .ops
        .iter()
        .filter(|op| matches!(op, StackOp::Placeholder { param_name, .. } if param_name == prop))
        .count()
}

/// A `load_prop` of a mutable variable-length state field must read the live
/// state: `_codePart` present (so `lower_deserialize_state` runs its
/// variable-length branch and pushes the property) and no deploy-time
/// placeholder anywhere in the method.
fn assert_reads_live_state(src: &str, label: &str) {
    let method = lower_check(src);
    assert!(
        method.uses_code_part,
        "{}: uses_code_part is false, so `_codePart` is never pushed and \
         lower_deserialize_state drops the scriptCode without deserialising \
         any mutable property",
        label
    );
    assert_eq!(
        placeholders_for(&method, "stored"),
        0,
        "{}: `stored` is read from its DEPLOY-TIME constructor placeholder \
         instead of the current on-chain state; ops = {:?}",
        label,
        method.ops
    );
}

#[test]
fn bytestring_state_field_reads_live_state_control() {
    assert_reads_live_state(BYTESTRING_CONTROL, "ByteString control");
}

#[test]
fn sig_state_field_reads_live_state() {
    assert_reads_live_state(SIG_STATE, "Sig state field");
}

#[test]
fn sighash_preimage_state_field_reads_live_state() {
    assert_reads_live_state(PREIMAGE_STATE, "SigHashPreimage state field");
}

/// The three surviving type lists in `codegen/stack.rs` must classify the same
/// set. Observable proxy: the ByteString control and the two bug cases lower to
/// the SAME opcode sequence apart from the pushed constants — identical op
/// COUNT is enough to catch a divergent branch being taken.
#[test]
fn sig_and_bytestring_state_take_the_same_lowering_path() {
    let control = lower_check(BYTESTRING_CONTROL);
    let sig = lower_check(SIG_STATE);
    let preimage = lower_check(PREIMAGE_STATE);
    assert_eq!(
        control.ops.len(),
        sig.ops.len(),
        "Sig state lowers down a different path than the ByteString control"
    );
    assert_eq!(
        control.ops.len(),
        preimage.ops.len(),
        "SigHashPreimage state lowers down a different path than the ByteString control"
    );
}
