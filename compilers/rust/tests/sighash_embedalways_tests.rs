//! Issue #123 (`@sighash`) + #109 (`@embedAlways`) — Rust tier.
//!
//! Ports the TypeScript reference suites (`sighash-validate.test.ts`,
//! `sighash-codegen.test.ts`, `embed-always.test.ts`). Covers the five
//! field-usage rejection rules, the mode-aware codegen (flag byte + ABI +
//! default byte-equivalence), and the @embedAlways DCE opt-out + warning.

use runar_compiler_rust::frontend::diagnostic::Severity;
use runar_compiler_rust::{compile_from_source_str_with_result, CompileOptions};

fn compile(src: &str, file: &str) -> runar_compiler_rust::CompileResult {
    compile_from_source_str_with_result(src, Some(file), &CompileOptions::default())
}

fn errors_of(src: &str) -> Vec<String> {
    compile(src, "X.runar.ts")
        .diagnostics
        .into_iter()
        .filter(|d| d.severity == Severity::Error)
        .map(|d| d.message)
        .collect()
}

fn warnings_of(src: &str) -> Vec<String> {
    compile(src, "X.runar.ts")
        .diagnostics
        .into_iter()
        .filter(|d| d.severity == Severity::Warning)
        .map(|d| d.message)
        .collect()
}

fn compiles(src: &str) -> bool {
    let r = compile(src, "X.runar.ts");
    r.artifact.is_some() && !r.diagnostics.iter().any(|d| d.severity == Severity::Error)
}

// ===========================================================================
// #123 — the five field-usage rejection rules (one test each)
// ===========================================================================

// Rule 1a: ANYONECANPAY zeroes hashPrevouts → reject extractHashPrevouts.
#[test]
fn rule1a_anyonecanpay_rejects_extract_hash_prevouts() {
    let src = r#"
    class Guard extends SmartContract {
      readonly expected: ByteString;
      constructor(expected: ByteString) { super(expected); this.expected = expected; }
      /** @sighash ALL|ANYONECANPAY|FORKID */
      public spend(pre: SigHashPreimage): void {
        assert(checkPreimage(pre));
        assert(extractHashPrevouts(pre) === this.expected);
      }
    }"#;
    assert!(
        errors_of(src).iter().any(|e| e.contains("hashPrevouts") && e.contains("zeroed under ANYONECANPAY")),
        "expected hashPrevouts/ANYONECANPAY rejection, got: {:?}",
        errors_of(src)
    );
}

// Rule 1b: ANYONECANPAY → reject a companion-input extractPrevOutputScript.
#[test]
fn rule1b_anyonecanpay_rejects_prev_output_script() {
    let src = r#"
    class Co extends StatefulSmartContract {
      readonly h0: ByteString;
      n: bigint;
      constructor(h0: ByteString, n: bigint) { super(h0, n); this.h0 = h0; this.n = n; }
      /** @sighash ALL|ANYONECANPAY|FORKID */
      public coSpend(): void {
        const s = extractPrevOutputScript(1n, this.h0);
        assert(len(s) > 0n);
      }
    }"#;
    assert!(
        errors_of(src).iter().any(|e| e.contains("companion input") || e.contains("prevout script")),
        "expected companion-input/prevout-script rejection, got: {:?}",
        errors_of(src)
    );
}

// Rule 2: hashSequence is zeroed under anything but pure ALL → reject.
#[test]
fn rule2_non_pure_all_rejects_extract_hash_sequence() {
    let src = r#"
    class Seq extends SmartContract {
      readonly expected: ByteString;
      constructor(expected: ByteString) { super(expected); this.expected = expected; }
      /** @sighash SINGLE|FORKID */
      public spend(pre: SigHashPreimage): void {
        assert(checkPreimage(pre));
        assert(extractHashSequence(pre) === this.expected);
      }
    }"#;
    assert!(
        errors_of(src).iter().any(|e| e.contains("hashSequence") && e.contains("zeroed")),
        "expected hashSequence rejection, got: {:?}",
        errors_of(src)
    );
}

// Rule 3: NONE commits to NO outputs → reject the state continuation.
#[test]
fn rule3_none_rejects_state_continuation() {
    let src = r#"
    class Counter extends StatefulSmartContract {
      n: bigint;
      constructor(n: bigint) { super(n); this.n = n; }
      /** @sighash NONE|FORKID */
      public bump(): void { this.n = this.n + 1n; }
    }"#;
    assert!(
        errors_of(src).iter().any(|e| e.contains("NONE commits to NO outputs") || e.contains("continuation")),
        "expected NONE continuation rejection, got: {:?}",
        errors_of(src)
    );
}

// Rule 4: SINGLE → reject the value-skimmable mutate-only auto-continuation.
#[test]
fn rule4_single_rejects_mutate_only_continuation() {
    let src = r#"
    class Counter extends StatefulSmartContract {
      n: bigint;
      constructor(n: bigint) { super(n); this.n = n; }
      /** @sighash SINGLE|FORKID */
      public bump(): void { this.n = this.n + 1n; }
    }"#;
    assert!(
        errors_of(src).iter().any(|e|
            e.contains("mutate-only SINGLE continuation is unsound")
                || e.contains("sized by the caller-chosen _newAmount")),
        "expected SINGLE mutate-only value-skim rejection, got: {:?}",
        errors_of(src)
    );
    assert!(!compiles(src));
}

// ===========================================================================
// #123 — additional security-audit rejections (e88f202c)
// ===========================================================================

#[test]
fn single_rejects_multi_output_continuation() {
    let src = r#"
    class Multi extends StatefulSmartContract {
      count: bigint;
      constructor(count: bigint) { super(count); this.count = count; }
      /** @sighash SINGLE|FORKID */
      public split(): void {
        this.addOutput(1000n, this.count);
        this.addOutput(2000n, this.count);
      }
    }"#;
    assert!(
        errors_of(src).iter().any(|e| e.contains("SINGLE commits ONLY to the output at this input")),
        "expected multi-output SINGLE rejection, got: {:?}",
        errors_of(src)
    );
}

#[test]
fn single_rejects_require_output_p2pkh() {
    let src = r#"
    class Cov extends StatefulSmartContract {
      readonly bondPKH: ByteString;
      readonly bond: bigint;
      constructor(bondPKH: ByteString, bond: bigint) { super(bondPKH, bond); this.bondPKH = bondPKH; this.bond = bond; }
      /** @sighash SINGLE|FORKID */
      public payBond() { requireOutputP2PKH(0n, this.bondPKH, this.bond); }
    }"#;
    assert!(
        errors_of(src).iter().any(|e|
            e.contains("requireOutputP2PKH") && e.contains("fixed index") && e.contains("SINGLE")),
        "expected requireOutputP2PKH/SINGLE rejection, got: {:?}",
        errors_of(src)
    );
}

// F3: transitive walk must cover the for-loop CONDITION.
#[test]
fn none_rejects_hashoutputs_read_in_for_condition() {
    let src = r#"
    class C extends SmartContract {
      readonly expected: ByteString;
      constructor(expected: ByteString) { super(expected); this.expected = expected; }
      /** @sighash NONE|FORKID */
      public spend(pre: SigHashPreimage): void {
        for (let i = 0n; i < 3n && extractOutputHash(pre) === this.expected; i++) { assert(i < 2n); }
        assert(checkPreimage(pre));
      }
    }"#;
    assert!(
        errors_of(src).iter().any(|e| e.contains("hashOutputs") && e.contains("zeroed under NONE")),
        "expected NONE hashOutputs rejection from for-condition, got: {:?}",
        errors_of(src)
    );
}

// ===========================================================================
// #123 — positive: the legitimate single-output SINGLE covenant warns
// ===========================================================================

#[test]
fn single_explicit_addoutput_accepts_with_warning() {
    let src = r#"
    class Pay extends StatefulSmartContract {
      n: bigint;
      constructor(n: bigint) { super(n); this.n = n; }
      /** @sighash SINGLE|FORKID */
      public settle(): void { this.addOutput(1000n, this.n); }
    }"#;
    assert!(compiles(src), "single-output SINGLE covenant should compile: {:?}", errors_of(src));
    assert!(
        warnings_of(src).iter().any(|w|
            w.contains("SINGLE commits ONLY to the output at this input")
                || w.contains("carries the FULL protected value")),
        "expected value-pinning warning, got: {:?}",
        warnings_of(src)
    );
}

// ===========================================================================
// #123 — the default (ALL|FORKID) is never flagged
// ===========================================================================

#[test]
fn default_mode_never_flagged() {
    // Every rejected body above compiles cleanly under the default mode.
    let bodies = [
        r#"class Counter extends StatefulSmartContract { n: bigint; constructor(n: bigint) { super(n); this.n = n; } public bump(): void { this.n = this.n + 1n; } }"#,
        r#"class Multi extends StatefulSmartContract { count: bigint; constructor(count: bigint) { super(count); this.count = count; } public split(): void { this.addOutput(1000n, this.count); this.addOutput(2000n, this.count); } }"#,
        r#"class Cov extends StatefulSmartContract { readonly bondPKH: ByteString; readonly bond: bigint; constructor(bondPKH: ByteString, bond: bigint) { super(bondPKH, bond); this.bondPKH = bondPKH; this.bond = bond; } public payBond() { requireOutputP2PKH(0n, this.bondPKH, this.bond); } }"#,
    ];
    for b in bodies {
        assert!(compiles(b), "default-mode body should compile: {:?}", errors_of(b));
    }
}

// ===========================================================================
// #123 — mode-aware codegen (mirrors sighash-codegen.test.ts)
// ===========================================================================

const COUNTER_OUT: &str = r#"
  class Counter extends StatefulSmartContract {
    n: bigint;
    constructor(n: bigint) { super(n); this.n = n; }
    DIRECTIVE
    public bump(): void { this.addOutput(1000n, this.n); }
  }"#;

fn counter_out(directive: &str) -> String {
    COUNTER_OUT.replace("DIRECTIVE", directive)
}

#[test]
fn default_script_byte_identical_to_explicit_all_forkid() {
    let no_directive = compile(&counter_out(""), "Counter.runar.ts");
    let explicit_all = compile(&counter_out("/** @sighash ALL|FORKID */"), "Counter.runar.ts");
    assert_eq!(
        no_directive.script_hex, explicit_all.script_hex,
        "ALL|FORKID must be byte-identical to the default"
    );
}

#[test]
fn single_forkid_script_contains_0x43_flag_and_differs_from_default() {
    let dflt = compile(&counter_out(""), "Counter.runar.ts");
    let single = compile(&counter_out("/** @sighash SINGLE|FORKID */"), "Counter.runar.ts");
    let single_hex = single.script_hex.clone().unwrap();
    let dflt_hex = dflt.script_hex.clone().unwrap();
    assert_ne!(single_hex, dflt_hex, "SINGLE must change the script");
    assert!(single_hex.contains("0143"), "SINGLE|FORKID must push the 0x43 flag byte");
    assert!(dflt_hex.contains("0141"), "default must push the 0x41 flag byte");
}

#[test]
fn abi_carries_sighash_type_for_non_default_only() {
    let single = compile(&counter_out("/** @sighash SINGLE|FORKID */"), "Counter.runar.ts");
    let dflt = compile(&counter_out(""), "Counter.runar.ts");
    let single_bump = single
        .artifact
        .unwrap()
        .abi
        .methods
        .into_iter()
        .find(|m| m.name == "bump")
        .unwrap();
    let dflt_bump = dflt
        .artifact
        .unwrap()
        .abi
        .methods
        .into_iter()
        .find(|m| m.name == "bump")
        .unwrap();
    assert_eq!(single_bump.sig_hash_type, Some(0x43));
    assert_eq!(dflt_bump.sig_hash_type, None);
}

#[test]
fn anyonecanpay_script_contains_0xc1_flag() {
    let src = r#"
      class Counter extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @sighash ALL|ANYONECANPAY|FORKID */
        public bump(): void { this.n = this.n + 1n; }
      }"#;
    let r = compile(src, "Counter.runar.ts");
    assert!(compiles(src), "ACP counter should compile: {:?}", errors_of(src));
    assert!(
        r.script_hex.unwrap().contains("01c1"),
        "ALL|ANYONECANPAY|FORKID must push the 0xC1 flag byte"
    );
}

// ===========================================================================
// #109 — @embedAlways DCE opt-out + warning (mirrors embed-always.test.ts)
// ===========================================================================

fn meta_src(directive: &str) -> String {
    format!(
        r#"
    class Meta extends SmartContract {{
      readonly pubKeyHash: Ripemd160;
      {}
      readonly metadataId: ByteString;
      constructor(pubKeyHash: Ripemd160, metadataId: ByteString) {{
        super(pubKeyHash, metadataId);
        this.pubKeyHash = pubKeyHash;
        this.metadataId = metadataId;
      }}
      public unlock(sig: Sig, pubKey: PubKey) {{
        assert(hash160(pubKey) === this.pubKeyHash);
        assert(checkSig(sig, pubKey));
      }}
    }}"#,
        directive
    )
}

#[test]
fn embed_always_un_annotated_field_eliminated_no_slot() {
    let r = compile(&meta_src(""), "Meta.runar.ts");
    assert!(r.artifact.is_some(), "{:?}", errors_of(&meta_src("")));
    // Un-annotated metadataId (param index 1) is DCE'd → only the pubKeyHash
    // slot (param index 0) survives.
    let slots = &r.artifact.unwrap().constructor_slots;
    assert!(
        !slots.iter().any(|s| s.param_index == 1),
        "un-annotated metadataId should be eliminated (no slot for param 1)"
    );
    assert!(slots.iter().any(|s| s.param_index == 0), "pubKeyHash slot must survive");
}

#[test]
fn embed_always_annotated_field_preserved_as_slot_and_longer_hex() {
    let off = compile(&meta_src(""), "Meta.runar.ts");
    let on = compile(&meta_src("/** @embedAlways */"), "Meta.runar.ts");
    let on_slots = &on.artifact.as_ref().unwrap().constructor_slots;
    assert!(
        on_slots.iter().any(|s| s.param_index == 1),
        "@embedAlways metadataId must be preserved as a constructor slot"
    );
    assert_ne!(off.script_hex, on.script_hex, "@embedAlways must change the script");
    assert!(
        on.script_hex.unwrap().len() > off.script_hex.unwrap().len(),
        "@embedAlways script must carry the extra field bytes"
    );
}

#[test]
fn embed_always_warns_for_stripped_field_and_not_for_annotated() {
    let off = warnings_of(&meta_src(""));
    assert!(
        off.iter().any(|w|
            w.contains("readonly field 'metadataId' is not referenced")
                && w.contains("eliminated by DCE")
                && w.contains("@embedAlways")),
        "expected DCE warning for stripped un-annotated field, got: {:?}",
        off
    );
    let on = warnings_of(&meta_src("/** @embedAlways */"));
    assert!(
        !on.iter().any(|w| w.contains("metadataId")),
        "annotated field must not warn, got: {:?}",
        on
    );
}

// ---------------------------------------------------------------------------
// #109 regression — @embedAlways must survive a FIXED-POINT DCE.
//
// The preservation used to be an alias pair: the injected `load_prop` plus a
// `load_const("@ref:<t>")` binding whose only job was to make the `load_prop`
// look referenced. That survives ONE DCE sweep but not the fixed-point loop in
// `frontend::dce`: sweep 1 drops the now-unreferenced alias, sweep 2 then drops
// the `load_prop` it was protecting, and BOTH halves vanish.
//
// DCE only runs from inside the EC optimizer's changed-gate (`optimize_ec`
// returns early when no rule fired), so the probe below has to arm it:
// `ecMulGen(1n)` folds to the generator constant (rule 6), which flips
// `changed` and lets dead-binding elimination run.
//
// Zig marks the injected `load_prop` itself with `preserve = true` and reads
// that flag in `hasSideEffect`; this tier now does the same.
// ---------------------------------------------------------------------------

/// EC-armed probe. `metadataId` (param 1) carries DIRECTIVE; `droppedField`
/// (param 2) is an un-annotated, unreferenced control that MUST still be
/// eliminated, so a passing test cannot be satisfied by "retain everything".
fn ec_meta_src(directive: &str) -> String {
    format!(
        r#"
    class EcMeta extends SmartContract {{
      readonly pubKeyHash: Ripemd160;
      {}
      readonly metadataId: ByteString;
      readonly droppedField: ByteString;
      constructor(pubKeyHash: Ripemd160, metadataId: ByteString, droppedField: ByteString) {{
        super(pubKeyHash, metadataId, droppedField);
        this.pubKeyHash = pubKeyHash;
        this.metadataId = metadataId;
        this.droppedField = droppedField;
      }}
      public unlock(sig: Sig, pubKey: PubKey) {{
        const g = ecMulGen(1n);
        assert(ecPointX(g) > 0n);
        assert(hash160(pubKey) === this.pubKeyHash);
        assert(checkSig(sig, pubKey));
      }}
    }}"#,
        directive
    )
}

#[test]
fn embed_always_survives_fixed_point_dce_in_ec_armed_method() {
    let src = ec_meta_src("/** @embedAlways */");
    let r = compile(&src, "EcMeta.runar.ts");
    assert!(r.artifact.is_some(), "{:?}", errors_of(&src));
    let slots = r.artifact.unwrap().constructor_slots;
    assert!(
        slots.iter().any(|s| s.param_index == 1),
        "@embedAlways metadataId must survive fixed-point DCE, slots: {:?}",
        slots.iter().map(|s| s.param_index).collect::<Vec<_>>()
    );
}

#[test]
fn ec_armed_un_annotated_dead_field_is_still_eliminated() {
    // Control: the fix must not degenerate into "keep every load_prop".
    for directive in ["", "/** @embedAlways */"] {
        let r = compile(&ec_meta_src(directive), "EcMeta.runar.ts");
        let slots = r.artifact.unwrap().constructor_slots;
        assert!(
            !slots.iter().any(|s| s.param_index == 2),
            "un-annotated droppedField must stay eliminated (directive={:?})",
            directive
        );
    }
}

#[test]
fn ec_armed_embed_always_changes_the_emitted_script() {
    let off = compile(&ec_meta_src(""), "EcMeta.runar.ts");
    let on = compile(&ec_meta_src("/** @embedAlways */"), "EcMeta.runar.ts");
    let off_hex = off.script_hex.unwrap();
    let on_hex = on.script_hex.unwrap();
    assert_ne!(off_hex, on_hex, "@embedAlways must change the EC-armed script");
    assert!(
        on_hex.len() > off_hex.len(),
        "annotated hex ({}) must exceed un-annotated ({})",
        on_hex.len(),
        off_hex.len()
    );
}
