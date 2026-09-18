//! R-067 regression guard for the Rust tier: fixed-arity lowering delegates
//! accepted over-supplied argument lists.
//!
//! Every fixed-arity delegate in `codegen/stack.rs` guarded its argument list
//! with a lower bound (`args.len() >= N`, or the `!args.is_empty()` spelling of
//! `>= 1`) rather than an equality. An argument list LONGER than the delegate
//! consumes was therefore accepted, and the surplus operand changed what the
//! emitted opcodes actually operated on. Two distinct mechanisms:
//!
//!   1. **Pairing shift (the crypto delegates).** `verifyRabinSig`,
//!      `verifyWOTS`, `verifySLHDSA_*`, `sha256Compress`, `sha256Finalize`,
//!      `blake3Compress` and `blake3Hash` marshal their operands with
//!      `for arg in args` — EVERY argument is physically brought to the top of
//!      the stack — and then pop a HARD-CODED count from the stack model before
//!      delegating. Give `sha256Compress(state, block)` a third operand and the
//!      real stack is `[.., state, block, decoy]` when the compression
//!      emission runs; it consumes the top two, so it compresses
//!      `(block, decoy)` while `state` is left stranded on the stack and the
//!      model believes it was consumed.
//!
//!      `oversupplied_crypto_delegate_emits_the_correct_arity_emission_shifted_by_one`
//!      pins that mechanism exactly: before the fix the over-supplied lowering
//!      was `[one surplus roll] ++ <the byte-identical correct-arity emission>`.
//!      The primitive's own opcodes never changed — only which stack slots they
//!      landed on. That is a hash or a signature verified against the wrong
//!      input, reported as success, with no diagnostic.
//!
//!   2. **Consume-flag flip (the index-addressed delegates).** `substr`,
//!      `right`, `__array_access` and the math helpers read `args[0]`,
//!      `args[1]`, ... and ignore anything past their arity — but they choose
//!      ROLL-vs-PICK through `operand_consume`, which decides by counting
//!      occurrences of the operand *in the whole `args` slice*:
//!      `operands.iter().filter(|o| *o == operand_ref).count() <= 1`. Appending
//!      a DUPLICATE of an operand already in the list flips that count above 1,
//!      so the operand is copied instead of moved and a stray value is left on
//!      the real stack while the model pops as if it had been consumed. The
//!      emitted script differs from the correct-arity script even though the
//!      surplus operand is never read.
//!
//! Reachability: the type checker's `check_call_args` (`frontend/typecheck.rs`)
//! DOES reject an over-supplied call on the source path, so a `.runar.*`
//! contract cannot reach either mechanism. The `--ir` entry point
//! (`compile_from_ir*` / `lower_to_stack`) runs no frontend validation in this
//! tier — the same gap R-016 was reachable through — so these guards are the
//! only thing standing between an over-supplied ANF IR input and a silently
//! mis-paired crypto primitive.
//!
//! The fix tightens every guard to an equality with the same "requires exactly
//! N arguments, got M" wording the tier already uses for `verifyECDSA_*` and
//! the TS reference uses for `poseidon2KB*`. Rejection is at compile time; no
//! opcode was added, which the byte-fingerprint controls below pin.

use runar_compiler_rust::codegen::stack::lower_to_stack;
use runar_compiler_rust::ir::loader::load_ir_from_str;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// A one-method contract whose body loads `n_params` parameters and then calls
/// `func` with the bindings named by `args` (indices into the loaded params).
fn call_anf(func: &str, n_params: usize, args: &[usize]) -> String {
    let params: Vec<String> = (0..n_params)
        .map(|i| format!(r#"{{ "name": "a{i}", "type": "ByteString" }}"#))
        .collect();
    let mut body: Vec<String> = (0..n_params)
        .map(|i| {
            format!(r#"{{ "name": "t{i}", "value": {{ "kind": "load_param", "name": "a{i}" }} }}"#)
        })
        .collect();
    let arg_list: Vec<String> = args.iter().map(|i| format!("\"t{i}\"")).collect();
    body.push(format!(
        r#"{{ "name": "tc", "value": {{ "kind": "call", "func": "{func}", "args": [{}] }} }}"#,
        arg_list.join(", ")
    ));
    body.push(r#"{ "name": "tv", "value": { "kind": "assert", "value": "tc" } }"#.to_string());
    format!(
        r#"{{ "contractName": "R067", "properties": [], "methods": [ {{ "name": "unlock", "params": [{}], "body": [{}], "isPublic": true }} ] }}"#,
        params.join(", "),
        body.join(", ")
    )
}

fn lower(func: &str, n_params: usize, args: &[usize]) -> Result<Vec<String>, String> {
    let program = load_ir_from_str(&call_anf(func, n_params, args))?;
    let methods = lower_to_stack(&program)?;
    Ok(methods[0].ops.iter().map(|o| format!("{:?}", o)).collect())
}

/// FNV-1a over the debug rendering of a method's op vector. A byte-exact
/// fingerprint with no extra dependency: any change to the emitted opcodes,
/// their order, or their operands moves it.
fn fingerprint(ops: &[String]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in ops.join("\u{1}").as_bytes() {
        h ^= *byte as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// The seven delegates that marshal `for arg in args` and then pop a hard-coded
/// count: an extra operand shifts which stack slots the primitive reads.
const PAIRING_SHIFT_SITES: &[(&str, usize)] = &[
    ("verifyRabinSig", 4),
    ("verifyWOTS", 3),
    ("verifySLHDSA_SHA2_128s", 3),
    ("sha256Compress", 2),
    ("sha256Finalize", 3),
    ("blake3Compress", 2),
    ("blake3Hash", 1),
];

/// The index-addressed delegates: a surplus DISTINCT operand is ignored, but a
/// surplus DUPLICATE operand flips `operand_consume` and strands a value.
const INDEX_ADDRESSED_SITES: &[(&str, usize)] = &[
    ("__array_access", 2),
    ("substr", 3),
    ("right", 2),
    ("safediv", 2),
    ("safemod", 2),
    ("clamp", 3),
    ("pow", 2),
    ("mulDiv", 3),
    ("percentOf", 2),
    ("gcd", 2),
    ("divmod", 2),
];

/// The `!args.is_empty()` spelling of `>= 1`. These five read `args[0]` via
/// `is_last_use` rather than `operand_consume`, so a surplus operand is inert —
/// but the guard is still a lower bound.
const SINGLE_OPERAND_SITES: &[(&str, usize)] = &[
    ("extractVersion", 1),
    ("reverseBytes", 1),
    ("sign", 1),
    ("sqrt", 1),
    ("log2", 1),
];

// ---------------------------------------------------------------------------
// The defect
// ---------------------------------------------------------------------------

/// The mechanism, pinned. Lower each crypto delegate twice against the SAME
/// contract shape — once at its real arity, once with one extra operand — and
/// show that the over-supplied lowering is the correct-arity lowering with a
/// surplus roll bolted onto the front. The primitive's emission is untouched;
/// only the operands underneath it moved. That is the mis-pairing.
///
/// After the fix the over-supplied form is refused, so the shifted emission
/// cannot be produced at all — which is exactly what this asserts.
#[test]
fn oversupplied_crypto_delegate_emits_the_correct_arity_emission_shifted_by_one() {
    for (func, arity) in PAIRING_SHIFT_SITES {
        let n_params = arity + 1;
        let correct: Vec<usize> = (0..*arity).collect();
        let over: Vec<usize> = (0..=*arity).collect();

        let correct_ops = lower(func, n_params, &correct)
            .unwrap_or_else(|e| panic!("{func} at its real arity must lower: {e}"));

        let over_ops = match lower(func, n_params, &over) {
            Err(_) => continue, // refused — the fix is in place for this site
            Ok(ops) => ops,
        };

        let shifted = over_ops.len() > correct_ops.len()
            && over_ops[over_ops.len() - correct_ops.len()..] == correct_ops[..];

        panic!(
            "{func} ACCEPTED {} operands (it consumes {arity}). The surplus \
             operand was marshalled to the top of the stack and the primitive's \
             emission ran on the shifted slots: over-supplied lowering is \
             `{:?} ++ <the byte-identical {arity}-operand emission>` \
             (suffix-identical: {shifted}). The primitive therefore reads \
             operands 2..={} instead of 1..={arity}, and operand 1 is stranded \
             on the stack while the model believes it was consumed.",
            over.len(),
            &over_ops[..over_ops.len() - correct_ops.len()],
            over.len(),
        );
    }
}

/// Every pairing-shift site must refuse an over-supplied call outright.
#[test]
fn oversupplied_crypto_delegates_are_refused() {
    for (func, arity) in PAIRING_SHIFT_SITES {
        let over: Vec<usize> = (0..=*arity).collect();
        match lower(func, arity + 1, &over) {
            Ok(ops) => panic!(
                "{func} consumes {arity} operands but ACCEPTED {} and emitted \
                 {} ops",
                over.len(),
                ops.len()
            ),
            Err(e) => {
                assert!(
                    e.contains(func) || e.contains("verifySLHDSA"),
                    "the diagnostic must name the delegate; got: {e}"
                );
                assert!(
                    e.contains("exactly"),
                    "the diagnostic must state that the arity is exact; got: {e}"
                );
            }
        }
    }
}

/// The index-addressed sites: a surplus DUPLICATE operand is the live case.
/// Before the fix this lowered to a script that differs from the correct-arity
/// script — `operand_consume` copied the operand instead of moving it and left
/// a stray value on the real stack.
#[test]
fn oversupplied_index_addressed_delegates_are_refused() {
    for (func, arity) in INDEX_ADDRESSED_SITES {
        // Surplus operand duplicating args[0] — the consume-flag flip.
        let mut dup: Vec<usize> = (0..*arity).collect();
        dup.push(0);
        match lower(func, *arity, &dup) {
            Ok(ops) => panic!(
                "{func} consumes {arity} operands but ACCEPTED {} (the surplus \
                 duplicates operand 1, flipping operand_consume from ROLL to \
                 PICK and stranding a value); emitted {} ops",
                dup.len(),
                ops.len()
            ),
            Err(e) => {
                assert!(e.contains(func), "diagnostic must name {func}; got: {e}");
                assert!(
                    e.contains("exactly"),
                    "diagnostic must state the arity is exact; got: {e}"
                );
            }
        }

        // Surplus DISTINCT operand — inert today, refused all the same.
        let over: Vec<usize> = (0..=*arity).collect();
        assert!(
            lower(func, arity + 1, &over).is_err(),
            "{func} accepted {} distinct operands for an arity-{arity} delegate",
            over.len()
        );
    }
}

/// The `!args.is_empty()` sites. A surplus operand is inert at these three, so
/// this is defence in depth rather than a live mis-pairing — but the guard is
/// the same lower bound and is tightened with the rest.
#[test]
fn oversupplied_single_operand_delegates_are_refused() {
    for (func, arity) in SINGLE_OPERAND_SITES {
        let over: Vec<usize> = (0..=*arity).collect();
        match lower(func, arity + 1, &over) {
            Ok(ops) => panic!(
                "{func} consumes 1 operand but ACCEPTED {} and emitted {} ops",
                over.len(),
                ops.len()
            ),
            Err(e) => {
                assert!(e.contains(func), "diagnostic must name {func}; got: {e}");
                assert!(
                    e.contains("exactly"),
                    "diagnostic must state the arity is exact; got: {e}"
                );
            }
        }
    }
}

/// Under-supply must stay refused too — the equality tightening must not lose
/// the lower bound it replaces.
#[test]
fn undersupplied_delegates_are_still_refused() {
    for (func, arity) in PAIRING_SHIFT_SITES
        .iter()
        .chain(INDEX_ADDRESSED_SITES)
        .chain(SINGLE_OPERAND_SITES)
    {
        let under: Vec<usize> = (0..arity - 1).collect();
        assert!(
            lower(func, *arity, &under).is_err(),
            "{func} accepted {} operands for an arity-{arity} delegate",
            under.len()
        );
    }
}

// ---------------------------------------------------------------------------
// Controls — the guard was tightened, codegen was NOT touched
// ---------------------------------------------------------------------------

/// Byte fingerprints of the correct-arity lowering of every one of the 23
/// sites, captured from the tier BEFORE the guards were tightened. A guard
/// change cannot move these; a codegen change would.
const CORRECT_ARITY_FINGERPRINTS: &[(&str, usize, usize, u64)] = &[
    // (func, arity, op count, FNV-1a of the op vector)
    ("verifyRabinSig", 4, 34, 0x32f3933061e6c9b4),
    // R-135: +3 top-level ops for the exact-signature-length gate (OP_SIZE,
    // push 2144, OP_EQUALVERIFY). 5444 -> 5447, and the fingerprint moves with it.
    ("verifyWOTS", 3, 5447, 0xeb5c21ad8b9fcfb4),
    ("verifySLHDSA_SHA2_128s", 3, 29583, 0xc1296427c5d591c0),
    ("sha256Compress", 2, 21296, 0x73b8dfa330f7de6f),
    ("sha256Finalize", 3, 63947, 0xfa3a224e6ba404f0),
    ("blake3Compress", 2, 10377, 0xdc81c38b475c9e46),
    ("blake3Hash", 1, 10387, 0x1b9842224c29f196),
    ("__array_access", 2, 10, 0x9fd1122314782f6a),
    ("substr", 3, 10, 0xa6268ef41498ed4a),
    ("right", 2, 10, 0x32227463aad02b43),
    ("safediv", 2, 8, 0xa371c23e3fab5f24),
    ("safemod", 2, 8, 0xc743ce4123866a1f),
    ("clamp", 3, 8, 0x8c2fc27cad9858cc),
    // R-169 (pow half): 168 -> 173 top-level ops. The 32 conditional-multiply
    // rounds are UNCHANGED; the +5 is the exponent-domain guard emitted ahead
    // of them (OP_DUP, push 0, push 33, OP_WITHIN, OP_VERIFY), without which
    // pow returned base^min(exp, 32) for any exponent and disagreed with both
    // the constant folder and the reference interpreter.
    ("pow", 2, 173, 0x902ca0077020ccea),
    ("mulDiv", 3, 8, 0x005f3b4b6679f2ff),
    ("percentOf", 2, 7, 0x1500fd62d3a9851e),
    ("gcd", 2, 777, 0x5377409bb251c204),
    ("divmod", 2, 10, 0x574b420e0160789c),
    // W1: 4 -> 6 top-level ops. The zero-pad (push 0x00, OP_CAT) before
    // OP_BIN2NUM, so the unsigned 32-bit nVersion field is not read as a
    // negative script number.
    ("extractVersion", 1, 6, 0x41fafbc2363896f1),
    ("reverseBytes", 1, 2083, 0xaa355cbc2102a10c),
    ("sign", 1, 2, 0x00a1c571bf6296bf),
    ("sqrt", 1, 10, 0xbfe239cb7a0312f2), // R-169: 2 -> 10 top-level ops (2 domain guards, 8 ops, ahead of the unchanged OP_DUP + OP_IF pair); the 256-round min-clamped Newton body lives inside the If and does not add top-level ops
    ("log2", 1, 386, 0x391ad77ad05d6a00),
];

#[test]
fn control_correct_arity_still_lowers_to_byte_identical_ops() {
    for (func, arity, expected_len, expected_fp) in CORRECT_ARITY_FINGERPRINTS {
        let args: Vec<usize> = (0..*arity).collect();
        let ops = lower(func, *arity, &args)
            .unwrap_or_else(|e| panic!("{func} at arity {arity} must still lower: {e}"));
        assert_eq!(
            ops.len(),
            *expected_len,
            "{func}: op count moved — the guard change altered codegen"
        );
        assert_eq!(
            fingerprint(&ops),
            *expected_fp,
            "{func}: emitted ops moved — the guard change altered codegen"
        );
    }
}

/// A repeated operand at the CORRECT arity is legitimate (`safediv(x, x)`) and
/// must keep compiling: the tightening counts arguments, it does not forbid a
/// duplicate. `operand_consume` still returns false here — correctly, since the
/// value really is needed twice — so this pins the PICK path as well.
#[test]
fn control_duplicate_operand_at_correct_arity_still_lowers() {
    let ops = lower("safediv", 1, &[0, 0]).expect("safediv(x, x) must still lower");
    assert_eq!(ops.len(), 7, "safediv(x, x) op count moved: {ops:?}");
    assert_eq!(
        fingerprint(&ops),
        0x9ad2_1744_546f_f20a,
        "safediv(x, x) emitted ops moved: {ops:?}"
    );
}
