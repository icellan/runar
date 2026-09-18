//! The off-chain Rust mock and the emitted script must agree.
//!
//! `packages/runar-rs` ships a Rust mock for (nearly) every codegen builtin. A
//! contract written in the `.runar.rs` DSL is BOTH native Rust (run by `cargo
//! test` against these mocks) AND Rúnar source (compiled to Script). Nothing in
//! this crate forced the two to produce the same value: the mock is
//! hand-maintained in `src/prelude.rs` and `src/ec.rs`, the emitter is
//! hand-maintained in `compilers/rust/src/codegen`, and a `compile_check` test
//! — the only test several of these contracts have — cannot see a value
//! mismatch at all.
//!
//! The Go tier grew this oracle first (`packages/runar-go/
//! mock_script_agreement_test.go`) and it immediately recorded three
//! divergences the compile tests had run past for the life of the repo. The
//! Rust tier had no equivalent: nothing under `packages/runar-rs` compiled a
//! builtin and executed it. This file is that missing oracle.
//!
//! For each builtin it compiles
//!
//! ```ignore
//! assert(<builtin>(args...) === expected)
//! ```
//!
//! with the Rust MOCK's output as `expected`, and runs the result through the
//! `bsv-sdk` `Spend` interpreter (`sdk::script_vm`, the same upstream
//! consensus interpreter the tier ships). Accepted => mock and emitter agree on
//! the value. Every case also runs a TAMPERED `expected` and requires
//! rejection, so a builtin whose script happens to accept anything cannot fake
//! agreement.
//!
//! The oracle is the executed script. Comparing the mock against itself, or
//! against a second Rust reimplementation, would prove nothing.
//!
//! # Width
//!
//! A row that exercises only in-range values is not coverage of a function that
//! truncates. The Go table already HAD a `bin2num` row before the truncation
//! was found — it passed `1000`, which fits — so the rows below that concern a
//! width-limited mock carry a value past 2^63, and `bin2num_sixteen_byte_push_
//! of_a_small_value` is the control that keeps the resulting guard keyed on the
//! VALUE rather than degenerating into "more than 8 bytes, therefore refuse":
//! Script numbers are not required to be minimally encoded, a 16-byte push of
//! 1000 is 1000, and the emitted opcodes accept it.

use num_bigint::{BigInt, Sign};
use runar_lang::ec::*;
use runar_lang::prelude::*;
use runar_lang::sdk::script_vm::{ScriptVm, VmOptions};

// ---------------------------------------------------------------------------
// Script-number / push-data encoding for the unlocking script
// ---------------------------------------------------------------------------

/// Encodes `n` in Bitcoin Script number form (little-endian sign-magnitude).
fn script_num(n: &BigInt) -> Vec<u8> {
    if n.sign() == Sign::NoSign {
        return Vec::new();
    }
    let neg = n.sign() == Sign::Minus;
    let (_, mag) = n.clone().into_parts();
    let be = mag.to_bytes_be();
    let mut le: Vec<u8> = be.into_iter().rev().collect();
    if le[le.len() - 1] & 0x80 != 0 {
        le.push(0);
    }
    if neg {
        let last = le.len() - 1;
        le[last] |= 0x80;
    }
    le
}

fn num_i(v: i64) -> Vec<u8> {
    script_num(&BigInt::from(v))
}

fn num_b(v: &BigInt) -> Vec<u8> {
    script_num(v)
}

fn boolean(v: bool) -> Vec<u8> {
    if v {
        vec![1]
    } else {
        Vec::new()
    }
}

/// A byte string differing from `v` in one bit — the non-vacuity control for
/// every case whose return type is a byte string.
fn tamper_bs(v: &[u8]) -> Vec<u8> {
    if v.is_empty() {
        return vec![0x01];
    }
    let mut b = v.to_vec();
    b[0] ^= 0xff;
    b
}

/// Minimal push encoding of one stack item, appended to `out`.
fn append_push(out: &mut Vec<u8>, data: &[u8]) {
    let hex = hex_of(data);
    let encoded = runar_lang::sdk::state::encode_push_data(&hex);
    out.extend_from_slice(&from_hex(&encoded));
}

fn hex_of(data: &[u8]) -> String {
    data.iter().map(|b| format!("{b:02x}")).collect()
}

fn from_hex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
        .collect()
}

/// The little-endian sign-magnitude encoding of `v` padded to `length` bytes.
///
/// The test's own encoder, deliberately independent of `prelude::num2bin` —
/// several rows below feed a value `num2bin` itself cannot represent, and a row
/// whose input came from the function under test would prove nothing.
fn wide_push(v: &BigInt, length: usize) -> Vec<u8> {
    let mut buf = vec![0u8; length];
    if v.sign() == Sign::NoSign {
        return buf;
    }
    let (_, mag) = v.clone().into_parts();
    let be = mag.to_bytes_be();
    assert!(be.len() <= length, "wide_push: {v} does not fit {length} bytes");
    for (i, b) in be.iter().enumerate() {
        buf[be.len() - 1 - i] = *b;
    }
    if v.sign() == Sign::Minus {
        buf[length - 1] |= 0x80;
    }
    buf
}

// ---------------------------------------------------------------------------
// One builtin under differential test
// ---------------------------------------------------------------------------

struct AgreementCase {
    /// The Rúnar name, as imported from 'runar-lang' and called.
    builtin: &'static str,
    /// The `packages/runar-rs` function under test (report only).
    mock: &'static str,
    /// Rúnar types of the call arguments, in order.
    arg_tys: Vec<&'static str>,
    /// Those arguments, encoded as Script stack items.
    args: Vec<Vec<u8>>,
    /// The Rúnar return type; `expected` is declared with it.
    ret_ty: &'static str,
    /// The MOCK's result, encoded as a Script stack item.
    want: Vec<u8>,
    /// A value distinct from `want`, for the non-vacuity control.
    tamper: Vec<u8>,
    /// Literal arguments appended AFTER the parameters, for builtins whose
    /// trailing argument must be a compile-time constant (`merkleRoot*` depth).
    call_extra: Vec<&'static str>,
    /// When non-empty, records that the mock is ALREADY known to disagree with
    /// the emitter, and why. Such a case INVERTS: the test requires the
    /// disagreement to still be there, so the mismatch stays recorded rather
    /// than silently tolerated, and the entry has to be deleted — not quietly
    /// kept — the day the mock is fixed.
    ///
    /// The inversion is what makes this an admission rather than a suppression.
    /// An entry that merely skipped the row would go stale the moment the mock
    /// was fixed and nobody would learn of it.
    known_divergent: &'static str,
}

impl AgreementCase {
    fn source(&self) -> String {
        let mut params = Vec::new();
        let mut call_args = Vec::new();
        for (i, ty) in self.arg_tys.iter().enumerate() {
            params.push(format!("p{i}: {ty}"));
            call_args.push(format!("p{i}"));
        }
        call_args.extend(self.call_extra.iter().map(|s| s.to_string()));
        params.push(format!("expected: {}", self.ret_ty));
        format!(
            r#"
import {{ SmartContract, assert, {b} }} from 'runar-lang';

class Diff extends SmartContract {{
  constructor() {{
    super();
  }}
  public verify({params}) {{
    assert({b}({call_args}) === expected);
  }}
}}
"#,
            b = self.builtin,
            params = params.join(", "),
            call_args = call_args.join(", "),
        )
    }
}

fn compile_agreement(c: &AgreementCase) -> Vec<u8> {
    let artifact = runar_compiler_rust::compile_from_source_str(&c.source(), Some("Diff.runar.ts"))
        .unwrap_or_else(|e| panic!("compile {} ({}): {e}", c.builtin, c.mock));
    assert!(
        !artifact.script.is_empty(),
        "{}: the compiler produced an empty script",
        c.builtin
    );
    from_hex(&artifact.script)
}

/// What the interpreter did with one spend.
#[derive(Debug, PartialEq, Eq)]
enum Spend {
    /// The script ran and accepted the value.
    Accepted,
    /// The script ran and evaluated to false — the value was REJECTED. This is
    /// the only outcome that carries information about the value.
    Rejected,
    /// The interpreter refused to execute the program at all. Says nothing
    /// whatever about the value; see `UNRUNNABLE` and `reconcile_unrunnable`.
    Refused(String),
}

/// Spends the compiled lock with `expected`.
fn run_agreement(lock: &[u8], c: &AgreementCase, expected: &[u8]) -> Spend {
    let mut unlock = Vec::new();
    for a in &c.args {
        append_push(&mut unlock, a);
    }
    append_push(&mut unlock, expected);
    let res = ScriptVm::new(VmOptions::default()).execute(&unlock, lock);
    match (res.success, res.error) {
        (true, _) => Spend::Accepted,
        (false, None) => Spend::Rejected,
        (false, Some(e)) => Spend::Refused(e),
    }
}

/// `true` when the interpreter refused to execute the PROGRAM, as opposed to
/// failing on these inputs.
///
/// The line is `DisabledOpcode` and nothing else. That error names an opcode
/// the interpreter will not run under ANY input, so no argument could have made
/// the row informative: the oracle never ran. Every other error — including
/// `InvalidStackOperation("num2bin: number too large for target size")` — is
/// input-dependent and IS a verdict about these arguments, so it must stay a
/// verdict and not be excused.
///
/// Counting an unrunnable row as agreement would be a guard that cannot fail;
/// counting it as disagreement would be a false finding against the mock. It is
/// neither, and the harness says so.
fn refused_identically(a: &Spend, b: &Spend) -> Option<String> {
    match (a, b) {
        (Spend::Refused(x), Spend::Refused(y)) if x == y && x.starts_with("DisabledOpcode") => {
            Some(x.clone())
        }
        _ => None,
    }
}

/// The verdict on one row.
enum Verdict {
    /// Mock and emitter agree.
    Agree,
    /// Something is wrong; the string says what.
    Failure(String),
    /// The interpreter would not execute this program. Nothing was learned.
    Unrunnable(String),
}

/// The whole protocol for one builtin.
fn check_agreement(c: &AgreementCase) -> Verdict {
    let lock = compile_agreement(c);
    eprintln!(
        "{:<22} {:<38} {:>7} script bytes; mock returned {}",
        c.builtin,
        c.mock,
        lock.len(),
        hex_of(&c.want)
    );

    if c.want == c.tamper {
        return Verdict::Failure(format!(
            "{} ({}): VACUOUS BY CONSTRUCTION — the control value equals the mock's own answer, \
             so the rejection below proves nothing about agreement",
            c.builtin, c.mock
        ));
    }

    // Control FIRST: a value the mock did NOT produce must be rejected.
    let control = run_agreement(&lock, c, &c.tamper);
    let verdict = run_agreement(&lock, c, &c.want);

    // Before anything else: did the oracle run at all?
    if let Some(err) = refused_identically(&control, &verdict) {
        return Verdict::Unrunnable(format!("{} ({}): {err}", c.builtin, c.mock));
    }

    if control == Spend::Accepted {
        return Verdict::Failure(format!(
            "{} ({}): VACUOUS — the script ACCEPTED a value the mock did not produce ({}). \
             No conclusion about mock/emitter agreement is possible.",
            c.builtin,
            c.mock,
            hex_of(&c.tamper)
        ));
    }

    if !c.known_divergent.is_empty() {
        return match verdict {
            Spend::Accepted => Verdict::Failure(format!(
                "{} ({}): now AGREES with the emitter, but this case is still on the \
                 known-divergent list ({}). Delete the known_divergent entry — a stale \
                 allowlist is how the next divergence hides.",
                c.builtin, c.mock, c.known_divergent
            )),
            other => {
                eprintln!(
                    "{} ({}): KNOWN DIVERGENCE still present ({}): {other:?}",
                    c.builtin, c.mock, c.known_divergent
                );
                Verdict::Agree
            }
        };
    }

    match verdict {
        Spend::Accepted => Verdict::Agree,
        other => Verdict::Failure(format!(
            "{} ({}): MOCK/EMITTER DISAGREE — the compiled script did not accept the value the \
             mock returned for the same inputs (mock said {}): {other:?}",
            c.builtin,
            c.mock,
            hex_of(&c.want)
        )),
    }
}

/// Runs a group of cases and fails once, naming every disagreement, so one
/// divergence does not hide the next. Returns the rows the interpreter refused
/// to execute, which are reconciled against the declared set separately.
fn run_group(name: &str, cases: Vec<AgreementCase>) -> Vec<String> {
    assert!(!cases.is_empty(), "{name}: empty case group — nothing was checked");
    let mut failures = Vec::new();
    let mut unrunnable = Vec::new();
    for c in &cases {
        match check_agreement(c) {
            Verdict::Agree => {}
            Verdict::Failure(f) => failures.push(f),
            Verdict::Unrunnable(u) => {
                eprintln!("UNRUNNABLE {u}");
                unrunnable.push(u);
            }
        }
    }
    if !failures.is_empty() {
        panic!(
            "{name}: {} of {} cases failed:\n  - {}",
            failures.len(),
            cases.len(),
            failures.join("\n  - ")
        );
    }
    unrunnable
}

/// Every row the `bsv-sdk` interpreter refuses to EXECUTE, and why.
///
/// `bsv-sdk` 0.2.89 rejects OP_2MUL and OP_2DIV unconditionally
/// (`src/script/spend_ops.rs`, "Disabled Opcodes"), with no post-Genesis
/// override — BSV re-enabled both at Genesis, and the Rust tier's EC codegen
/// emits OP_2MUL. So for these three builtins the Rust ScriptVm cannot run the
/// Rust compiler's own output, and no agreement or disagreement can be
/// observed. The Go tier's interpreter takes `WithAfterGenesis()` and runs
/// them; that is where these three builtins are actually covered.
///
/// Both directions are covered, but by two different mechanisms, and the
/// distinction matters to anyone changing this.
///
/// FORWARD — a row that becomes unrunnable without being listed is caught by
/// `reconcile_unrunnable` below, which is called per group and fails on any
/// refusal it does not expect.
///
/// REVERSE — a listed row that starts running is NOT caught there. That check
/// is called with one group's observations at a time, so it cannot tell an entry
/// belonging to another group from a stale one, and computing
/// `UNRUNNABLE \ observed` per call would fire on every group but its own.
/// The reverse guarantee comes instead from
/// `the_interpreter_refuses_op_2mul_which_is_why_three_ec_rows_are_excused`,
/// which pins the single reason all three entries exist: bsv-sdk refusing
/// OP_2MUL unconditionally. If that stops being true, that test fails and says
/// to re-run these three and delete the ones that now execute. One root cause,
/// one pin — rather than three entries each asserting their own excuse.
///
/// This comment previously claimed the list was "a ratchet in both directions"
/// and pointed at `unrunnable_rows_are_exactly_the_declared_set`, which does not
/// exist and never did. The guarantee was real; the mechanism described was not.
const UNRUNNABLE: &[&str] = &[
    "ecAdd (ec_add)",
    "ecMulGen (ec_mul_gen)",
    "ecMul (ec_mul)",
];

/// Reconciles what the interpreter actually refused against `UNRUNNABLE`.
fn reconcile_unrunnable(observed: &[String]) {
    let mut unexpected = Vec::new();
    for o in observed {
        let head = o.split(": ").next().unwrap_or(o).to_string();
        if !UNRUNNABLE.contains(&head.as_str()) {
            unexpected.push(o.clone());
        }
    }
    assert!(
        unexpected.is_empty(),
        "the interpreter refused to execute a row that is not on the UNRUNNABLE list — \
         these rows proved NOTHING and were about to be counted as coverage:\n  - {}",
        unexpected.join("\n  - ")
    );
}

// ---------------------------------------------------------------------------
// Case constructors
// ---------------------------------------------------------------------------

/// An all-`bigint` case whose mock answer fits i64.
fn int_case(builtin: &'static str, mock: &'static str, want: i64, args: &[i64]) -> AgreementCase {
    AgreementCase {
        builtin,
        mock,
        arg_tys: vec!["bigint"; args.len()],
        args: args.iter().map(|a| num_i(*a)).collect(),
        ret_ty: "bigint",
        want: num_i(want),
        tamper: num_i(want.wrapping_add(1)),
        call_extra: vec![],
        known_divergent: "",
    }
}

/// An all-`bigint` case returning a boolean.
fn bool_case(builtin: &'static str, mock: &'static str, want: bool, args: &[i64]) -> AgreementCase {
    AgreementCase {
        builtin,
        mock,
        arg_tys: vec!["bigint"; args.len()],
        args: args.iter().map(|a| num_i(*a)).collect(),
        ret_ty: "boolean",
        want: boolean(want),
        tamper: boolean(!want),
        call_extra: vec![],
        known_divergent: "",
    }
}

/// A case whose arguments and result are byte strings.
fn bytes_case(
    builtin: &'static str,
    mock: &'static str,
    arg_tys: Vec<&'static str>,
    args: Vec<Vec<u8>>,
    ret_ty: &'static str,
    want: Vec<u8>,
) -> AgreementCase {
    AgreementCase {
        builtin,
        mock,
        arg_tys,
        args,
        ret_ty,
        tamper: tamper_bs(&want),
        want,
        call_extra: vec![],
        known_divergent: "",
    }
}

// ---------------------------------------------------------------------------
// Math
// ---------------------------------------------------------------------------

#[test]
fn math_builtins_agree_with_the_emitter() {
    reconcile_unrunnable(&run_group(
        "math",
        vec![
            int_case("abs", "abs", abs(-7), &[-7]),
            int_case("min", "min", min(7, 3), &[7, 3]),
            int_case("max", "max", max(7, 3), &[7, 3]),
            int_case("safediv", "safediv", safediv(17, 5), &[17, 5]),
            int_case("safemod", "safemod", safemod(17, 5), &[17, 5]),
            int_case("clamp", "clamp", clamp(15, 1, 10), &[15, 1, 10]),
            int_case("sign", "sign", sign(-9), &[-9]),
            int_case("pow", "pow", pow(3, 5), &[3, 5]),
            int_case("mulDiv", "mul_div", mul_div(7, 11, 3), &[7, 11, 3]),
            int_case("percentOf", "percent_of", percent_of(1000, 250), &[1000, 250]),
            int_case("sqrt", "sqrt", sqrt(1000), &[1000]),
            int_case("gcd", "gcd", gcd(462, 1071), &[462, 1071]),
            int_case("divmod", "divmod", divmod(17, 5), &[17, 5]),
            int_case("log2", "log2", log2(1000), &[1000]),
            bool_case("within", "within", within(5, 1, 10), &[5, 1, 10]),
            bool_case("bool", "bool", bool(5), &[5]),
            // `bool_cast` is a second mock of the SAME builtin (the Rust
            // surface resolves both spellings to `bool`), so it gets its own
            // row the way Go's Int2Str / Int2str do: two functions, one
            // emitter, and nothing else compares them.
            bool_case("bool", "bool_cast", bool_cast(5), &[5]),
        ],
    ));
}

// ---------------------------------------------------------------------------
// Byte strings
// ---------------------------------------------------------------------------

/// A value past i64. Every width row below is built from it.
fn wide_value() -> BigInt {
    "123456789012345678901234567890".parse().unwrap()
}

#[test]
fn byte_string_builtins_agree_with_the_emitter() {
    let src: Vec<u8> = vec![0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe];
    reconcile_unrunnable(&run_group(
        "byte strings",
        vec![
            bytes_case(
                "cat",
                "cat",
                vec!["ByteString", "ByteString"],
                vec![vec![0xde, 0xad], vec![0xbe, 0xef]],
                "ByteString",
                cat(&[0xde, 0xad], &[0xbe, 0xef]),
            ),
            bytes_case(
                "substr",
                "substr",
                vec!["ByteString", "bigint", "bigint"],
                vec![src.clone(), num_i(1), num_i(3)],
                "ByteString",
                substr(&src, 1, 3),
            ),
            bytes_case(
                "num2bin",
                "num2bin",
                vec!["bigint", "bigint"],
                vec![num_i(1000), num_i(8)],
                "ByteString",
                num2bin(&1000, 8),
            ),
            {
                let data = vec![0xe8, 0x03];
                let want = bin2num(&data);
                AgreementCase {
                    builtin: "bin2num",
                    mock: "bin2num",
                    arg_tys: vec!["ByteString"],
                    args: vec![data],
                    ret_ty: "bigint",
                    want: num_i(want),
                    tamper: num_i(want + 1),
                    call_extra: vec![],
                    known_divergent: "",
                }
            },
        ],
    ));
}

// ---------------------------------------------------------------------------
// The eight byte builtins `packages/runar-rs` had no mock for
// ---------------------------------------------------------------------------
//
// `len`, `split`, `left`, `right`, `int2str`, `int_2_str`, `reverse_bytes` and
// `to_byte_string` are all documented as callable in `docs/formats/rust.md` and
// none of them existed in this crate. A mock that does not exist cannot
// disagree with an emitter, which is exactly how the gap survived: the seven
// `.runar.rs` contracts calling one of them could not be compiled as Rust at
// all, so the only thing that ever read them was the Rúnar frontend.
//
// Every row below spends the compiled lock. The mock's own answer is the
// `expected` the script has to accept, and a tampered value has to be rejected
// first, so "the script accepts anything" cannot pass for agreement.

/// A byte-string argument case whose answer is a byte string.
fn bs_case(
    builtin: &'static str,
    mock: &'static str,
    arg_tys: Vec<&'static str>,
    args: Vec<Vec<u8>>,
    want: Vec<u8>,
) -> AgreementCase {
    bytes_case(builtin, mock, arg_tys, args, "ByteString", want)
}

/// Sixteen distinct bytes: a cut at any position is visible in the result.
fn sixteen() -> Vec<u8> {
    (1u8..=16).collect()
}

/// The largest element the emitted `reverseBytes` loop can reverse in full.
fn five_twenty() -> Vec<u8> {
    (0..520).map(|i| (i % 251) as u8).collect()
}

#[test]
fn len_agrees_with_the_emitter() {
    let d = sixteen();
    let big = five_twenty();
    reconcile_unrunnable(&run_group(
        "len",
        vec![
            AgreementCase {
                builtin: "len",
                mock: "len",
                arg_tys: vec!["ByteString"],
                args: vec![d.clone()],
                ret_ty: "bigint",
                want: num_i(len(&d)),
                tamper: num_i(len(&d) + 1),
                call_extra: vec![],
                known_divergent: "",
            },
            // Empty. `OP_SIZE` of an empty element is 0, not a failure, and the
            // Script encoding of 0 is the EMPTY push — the one case where
            // `want` and a wrong answer are most easily confused.
            AgreementCase {
                builtin: "len",
                mock: "len (empty value)",
                arg_tys: vec!["ByteString"],
                args: vec![Vec::new()],
                ret_ty: "bigint",
                want: num_i(len(&[])),
                tamper: num_i(1),
                call_extra: vec![],
                known_divergent: "",
            },
            // 520 bytes: past one byte of Script number, and the element-size
            // bound every emitter is built around. A `len` that answered from
            // anything narrower than the whole value still looks right at 16.
            AgreementCase {
                builtin: "len",
                mock: "len (520-byte value)",
                arg_tys: vec!["ByteString"],
                args: vec![big.clone()],
                ret_ty: "bigint",
                want: num_i(len(&big)),
                tamper: num_i(len(&big) - 1),
                call_extra: vec![],
                known_divergent: "",
            },
        ],
    ));
    assert_eq!(len(&big), 520, "the 520-byte row is not 520 bytes");
}

#[test]
fn split_left_and_right_agree_with_the_emitter() {
    let d = sixteen();
    reconcile_unrunnable(&run_group(
        "split / left / right",
        vec![
            // `split` binds the RIGHT half (OP_SPLIT OP_NIP). A mock returning
            // the left half, or a pair, would be rejected here.
            bs_case("split", "split", vec!["ByteString", "bigint"], vec![d.clone(), num_i(5)], split(&d, 5)),
            bs_case(
                "split",
                "split (at zero)",
                vec!["ByteString", "bigint"],
                vec![d.clone(), num_i(0)],
                split(&d, 0),
            ),
            // At `len` the cut yields the empty byte string, which is also the
            // Script encoding of 0 and of false — the answer most likely to be
            // produced for the wrong reason.
            bs_case(
                "split",
                "split (at len)",
                vec!["ByteString", "bigint"],
                vec![d.clone(), num_i(16)],
                split(&d, 16),
            ),
            bs_case(
                "split",
                "split (empty value at zero)",
                vec!["ByteString", "bigint"],
                vec![Vec::new(), num_i(0)],
                split(&[], 0),
            ),
            bs_case("left", "left", vec!["ByteString", "bigint"], vec![d.clone(), num_i(5)], left(&d, 5)),
            bs_case(
                "left",
                "left (whole value)",
                vec!["ByteString", "bigint"],
                vec![d.clone(), num_i(16)],
                left(&d, 16),
            ),
            bs_case(
                "left",
                "left (nothing)",
                vec!["ByteString", "bigint"],
                vec![d.clone(), num_i(0)],
                left(&d, 0),
            ),
            bs_case("right", "right", vec!["ByteString", "bigint"], vec![d.clone(), num_i(5)], right(&d, 5)),
            bs_case(
                "right",
                "right (whole value)",
                vec!["ByteString", "bigint"],
                vec![d.clone(), num_i(16)],
                right(&d, 16),
            ),
            bs_case(
                "right",
                "right (nothing)",
                vec!["ByteString", "bigint"],
                vec![d.clone(), num_i(0)],
                right(&d, 0),
            ),
        ],
    ));

    // `split` and `left` are the two sides of ONE cut. Each row above pins one
    // side against the script; without this the two could be wrong in
    // compensating ways and both rows would still pass.
    assert_eq!(cat(&left(&d, 5), &split(&d, 5)), d, "left and split do not reassemble the value");
}

/// Past the end, `OP_SPLIT` FAILS — it does not clamp — so the mock has to
/// refuse rather than answer. A value-agreement row cannot express this: the
/// script aborts on the ARGUMENTS and never reaches the comparison, whatever
/// `expected` is. Same shape as the `num2bin` refusal-parity tests above.
#[test]
fn split_refuses_a_position_past_the_end_and_so_must_the_mock() {
    let d = sixteen();
    let c = AgreementCase {
        builtin: "split",
        mock: "probe",
        arg_tys: vec!["ByteString", "bigint"],
        args: vec![d.clone(), num_i(17)],
        ret_ty: "ByteString",
        want: Vec::new(),
        tamper: vec![0x01],
        call_extra: vec![],
        known_divergent: "",
    };
    let lock = compile_agreement(&c);

    match run_agreement(&lock, &c, &c.want) {
        Spend::Refused(e) => assert!(
            e.contains("InvalidSplitRange") || e.contains("Split") || e.contains("split"),
            "the emitted split failed past the end, but not on the split: {e}"
        ),
        other => panic!(
            "the emitted split ACCEPTED or merely rejected position 17 on a 16-byte value \
             ({other:?}) — this test's premise is gone, and the mock's refusal below would \
             then be the divergence"
        ),
    }

    let mock = std::panic::catch_unwind(|| split(&sixteen(), 17));
    assert!(
        mock.is_err(),
        "MOCK/EMITTER DISAGREE — the emitted split FAILS at position 17 of a 16-byte value, \
         but prelude::split returned {:?}. Whatever that is, it is a value on-chain \
         execution can never produce.",
        mock.map(|v| hex_of(&v))
    );

    // And the in-range side, so the refusal above is about the position rather
    // than about `split` refusing everything.
    assert_eq!(split(&sixteen(), 16), Vec::<u8>::new());
}

#[test]
fn reverse_bytes_agrees_with_the_emitter() {
    let big = five_twenty();
    reconcile_unrunnable(&run_group(
        "reverseBytes",
        vec![
            bs_case(
                "reverseBytes",
                "reverse_bytes",
                vec!["ByteString"],
                vec![vec![0xde, 0xad, 0xbe, 0xef]],
                reverse_bytes(&[0xde, 0xad, 0xbe, 0xef]),
            ),
            // One byte is its own reverse, so this row can only be read
            // together with the control: the tampered value must be rejected.
            bs_case(
                "reverseBytes",
                "reverse_bytes (one byte)",
                vec!["ByteString"],
                vec![vec![0x7f]],
                reverse_bytes(&[0x7f]),
            ),
            // An odd length has a fixed middle byte; an implementation that
            // pairs bytes off the ends can drop or duplicate it and still pass
            // every even-length case.
            bs_case(
                "reverseBytes",
                "reverse_bytes (odd length)",
                vec!["ByteString"],
                vec![vec![1, 2, 3, 4, 5]],
                reverse_bytes(&[1, 2, 3, 4, 5]),
            ),
            // 520 bytes is the bound the loop is unrolled to — the last length
            // the script reverses in full, and the one the mock's own refusal
            // above it is keyed on.
            bs_case(
                "reverseBytes",
                "reverse_bytes (520 bytes, the unroll bound)",
                vec!["ByteString"],
                vec![big.clone()],
                reverse_bytes(&big),
            ),
        ],
    ));

    // The empty value is separate: `reverse_bytes(&[])` is the empty byte
    // string, which is also what a tampered control would have to differ from,
    // and `tamper_bs` of empty is `[0x01]` — a real difference, so the row is
    // not vacuous. Kept out of the group only because it reads better named.
    reconcile_unrunnable(&run_group(
        "reverseBytes (empty)",
        vec![bs_case(
            "reverseBytes",
            "reverse_bytes (empty value)",
            vec!["ByteString"],
            vec![Vec::new()],
            reverse_bytes(&[]),
        )],
    ));
}

/// Past 520 bytes the emitted loop runs out of iterations and DROPS the
/// unconsumed remainder, so the script returns the reverse of the first 520
/// bytes. A mock that reversed the whole value would hand the caller a value
/// on-chain execution cannot produce — the `num2bin` failure mode exactly — so
/// it refuses, and this pins the bound rather than asserting it in a comment.
#[test]
fn reverse_bytes_refuses_past_the_unroll_bound() {
    let mock = std::panic::catch_unwind(|| reverse_bytes(&vec![0u8; REVERSE_BYTES_MAX + 1]));
    assert!(
        mock.is_err(),
        "prelude::reverse_bytes answered for {} bytes. Every tier unrolls exactly {} \
         peel-one-byte iterations and then drops what is left, so the script's answer is \
         the reverse of only the first {} bytes and the mock's is not it.",
        REVERSE_BYTES_MAX + 1,
        REVERSE_BYTES_MAX,
        REVERSE_BYTES_MAX
    );
    // The bound itself must be ACCEPTED, or the refusal above would pass for a
    // mock that refuses everything.
    assert_eq!(reverse_bytes(&vec![0u8; REVERSE_BYTES_MAX]).len(), REVERSE_BYTES_MAX);
}

#[test]
fn int2str_agrees_with_the_emitter() {
    reconcile_unrunnable(&run_group(
        "int2str",
        vec![
            bs_case("int2str", "int2str", vec!["bigint", "bigint"], vec![num_i(1000), num_i(4)], int2str(1000, 4)),
            // Zero: every byte of the answer is 0x00, and the ARGUMENT is the
            // empty push. A mock keyed on the argument's length rather than its
            // value gets this one wrong.
            bs_case(
                "int2str",
                "int2str (zero)",
                vec!["bigint", "bigint"],
                vec![num_i(0), num_i(4)],
                int2str(0, 4),
            ),
            // Negative: the sign is the top bit of the LAST byte, not a
            // separate byte, and not the first byte.
            bs_case(
                "int2str",
                "int2str (negative)",
                vec!["bigint", "bigint"],
                vec![num_i(-1000), num_i(4)],
                int2str(-1000, 4),
            ),
            // 255 in two bytes: the sign occupies the bit the magnitude would
            // otherwise use, so the answer is `ff00` and not `ff`.
            bs_case(
                "int2str",
                "int2str (sign needs its own bit)",
                vec!["bigint", "bigint"],
                vec![num_i(255), num_i(2)],
                int2str(255, 2),
            ),
            // The `int_2_str` spelling is a SECOND mock of the same builtin —
            // both parser spellings lower to `int2str` — so it gets its own row
            // the way `bool` / `bool_cast` does. Nothing else compares them.
            bs_case(
                "int2str",
                "int_2_str",
                vec!["bigint", "bigint"],
                vec![num_i(-1000), num_i(4)],
                int_2_str(-1000, 4),
            ),
        ],
    ));
}

/// `int2str` IS `OP_NUM2BIN`, so it inherits the refusal: the opcode fails when
/// the number does not fit the size and has no wrap-around. The emitted script
/// is checked here rather than the claim being inherited from the `num2bin`
/// tests — `int2str` reaches the opcode down a different path in every tier.
#[test]
fn int2str_refuses_a_width_too_small_and_so_must_the_mock() {
    let c = AgreementCase {
        builtin: "int2str",
        mock: "probe",
        arg_tys: vec!["bigint", "bigint"],
        args: vec![num_i(1000), num_i(1)],
        ret_ty: "ByteString",
        want: vec![0x00],
        tamper: vec![0x01],
        call_extra: vec![],
        known_divergent: "",
    };
    let lock = compile_agreement(&c);
    let err = match run_agreement(&lock, &c, &c.want) {
        Spend::Refused(e) => e,
        other => panic!(
            "the emitted int2str ACCEPTED or merely rejected 1000 in one byte ({other:?}) — \
             this test's premise is gone"
        ),
    };
    assert!(
        err.contains("too large for target size"),
        "expected the emitted int2str to fail on the size, got: {err}"
    );

    let mock = std::panic::catch_unwind(|| int2str(1000, 1));
    assert!(
        mock.is_err(),
        "MOCK/EMITTER DISAGREE — the emitted int2str FAILS on int2str(1000, 1) ({err}), but \
         prelude::int2str returned {:?}.",
        mock.map(|v| hex_of(&v))
    );

    // Two bytes is the width that works, so the refusal is about the width.
    assert_eq!(hex_of(&int2str(1000, 2)), "e803");
}

/// `toByteString` is the identity on bytes already pushed — `spec/grammar.md`
/// makes `toByteString '(' StringLiteral ')'` the ByteStringLiteral production,
/// so the hex IS the value. The claim this row settles is therefore about the
/// mock's hex DECODER: the bytes it produces for a spelling must be the bytes
/// the script sees for that same literal.
#[test]
fn to_byte_string_agrees_with_the_emitter() {
    let cases: &[&str] = &[
        "deadbeef",
        // Empty: a decoder that returned a one-byte zero, or refused, would
        // still pass every non-empty case.
        "",
        // Leading zero bytes are load-bearing in a fixed-width value and are
        // the first thing a "parse as a number then re-encode" decoder loses.
        "0000ff",
        // Mixed case, both digits of a byte crossing the a-f boundary.
        "0aF0",
        // A byte with the high bit set, which is the sign bit in a Script
        // number and must NOT be treated as one here.
        "80",
    ];
    reconcile_unrunnable(&run_group(
        "toByteString",
        cases
            .iter()
            .map(|hex| {
                let want = to_byte_string(hex);
                AgreementCase {
                    builtin: "toByteString",
                    mock: "to_byte_string",
                    arg_tys: vec!["ByteString"],
                    args: vec![want.clone()],
                    ret_ty: "ByteString",
                    tamper: tamper_bs(&want),
                    want,
                    call_extra: vec![],
                    known_divergent: "",
                }
            })
            .collect(),
    ));

    // The argument pushed above IS the mock's own answer, so those rows pin the
    // SCRIPT's identity, not the decoder. This pins the decoder, against a
    // spelling written out byte by byte rather than re-derived from it.
    assert_eq!(to_byte_string("0aF0"), vec![0x0a, 0xf0]);
    assert_eq!(to_byte_string(""), Vec::<u8>::new());

    for bad in ["abc", "gg", "0x41", " 41"] {
        assert!(
            std::panic::catch_unwind(|| to_byte_string(bad)).is_err(),
            "to_byte_string({bad:?}) returned a value; that spelling denotes no byte string"
        );
    }
}

// ---------------------------------------------------------------------------
// Width — the rows that go past 2^63
// ---------------------------------------------------------------------------

/// `bin2num` of a push carrying a value i64 cannot hold.
///
/// This is the row the Go tier's table was missing when it "covered" bin2num
/// with 1000. `OP_BIN2NUM` leaves the whole value on the stack; a mock that
/// returns the low 64 bits returns a different number and nothing says so.
#[test]
fn bin2num_past_2_63_agrees_with_the_emitter() {
    let wide = wide_value();
    let data = wide_push(&wide, 16);
    let want = bin2num_big(&data);
    assert_eq!(want, wide, "bin2num_big did not decode the value the test encoded");
    reconcile_unrunnable(&run_group(
        "bin2num past 2^63",
        vec![AgreementCase {
            builtin: "bin2num",
            mock: "bin2num_big",
            arg_tys: vec!["ByteString"],
            args: vec![data.clone()],
            ret_ty: "bigint",
            want: num_b(&want),
            tamper: num_b(&(&want + 1)),
            call_extra: vec![],
            known_divergent: "",
        }],
    ));

    // The narrow mock must REFUSE this push rather than answer it. Without
    // this, `bin2num` could go on returning -4362896299872285998 and the row
    // above — which calls the wide form — would stay green.
    let narrow = std::panic::catch_unwind(|| bin2num(&data));
    assert!(
        narrow.is_err(),
        "prelude::bin2num returned {:?} for a value that does not fit i64. OP_BIN2NUM has no \
         such limit, so that number is not the one the script produces, and a mock that \
         answers instead of refusing hands the caller a wrong value silently.",
        narrow.ok()
    );
}

/// The boundary is the VALUE, not the push width.
///
/// A guard that refused anything wider than eight bytes would satisfy the
/// refusal test and still be wrong: Script numbers need not be minimally
/// encoded, a 16-byte push of 1000 is 1000, and the emitted opcodes accept it.
#[test]
fn bin2num_sixteen_byte_push_of_a_small_value_agrees_with_the_emitter() {
    let data = wide_push(&BigInt::from(1000), 16);
    let want = bin2num(&data);
    assert_eq!(want, 1000, "the 16-byte push does not carry 1000");
    reconcile_unrunnable(&run_group(
        "bin2num, 16-byte push, in-range value",
        vec![AgreementCase {
            builtin: "bin2num",
            mock: "bin2num (16-byte push, in-range value)",
            arg_tys: vec!["ByteString"],
            args: vec![data],
            ret_ty: "bigint",
            want: num_i(want),
            tamper: num_i(want + 1),
            call_extra: vec![],
            known_divergent: "",
        }],
    ));
}

// ---------------------------------------------------------------------------
// Refusal parity — where the script REFUSES, the mock must refuse too
// ---------------------------------------------------------------------------
//
// `OP_NUM2BIN` fails when the number does not fit the requested size; it has no
// wrap-around. A value-agreement row cannot express that, because the script
// aborts on the ARGUMENTS and never reaches the comparison — whatever
// `expected` is. The question there is not "do the two answers match" but "does
// the mock refuse what the script refuses", and a mock that returns bytes where
// the script fails is handing the caller a value on-chain execution can never
// produce.

/// Does the compiled `num2bin(v, width)` execute at all for these arguments?
fn script_num2bin_accepts(v: &BigInt, width: i64) -> Result<Vec<u8>, String> {
    let src = format!(
        r#"
import {{ SmartContract, assert, num2bin, len }} from 'runar-lang';

class N2B extends SmartContract {{
  constructor() {{
    super();
  }}
  public verify(p0: bigint, p1: bigint, expected: ByteString) {{
    assert(num2bin(p0, p1) === expected);
  }}
}}
"#
    );
    let artifact = runar_compiler_rust::compile_from_source_str(&src, Some("N2B.runar.ts"))
        .map_err(|e| format!("compile: {e}"))?;
    let lock = from_hex(&artifact.script);
    // `expected` is irrelevant when the opcode itself fails. When the width
    // DOES hold the value, push the encoding the script must produce, so a
    // spend that runs also checks the bytes rather than merely not aborting.
    let w = width.max(0) as usize;
    let (_, mag) = v.clone().into_parts();
    let probe = if mag.to_bytes_be().len() <= w {
        wide_push(v, w)
    } else {
        vec![0u8; w]
    };
    let c = AgreementCase {
        builtin: "num2bin",
        mock: "probe",
        arg_tys: vec!["bigint", "bigint"],
        args: vec![num_b(v), num_i(width)],
        ret_ty: "ByteString",
        want: probe.clone(),
        tamper: tamper_bs(&probe),
        call_extra: vec![],
        known_divergent: "",
    };
    match run_agreement(&lock, &c, &probe) {
        Spend::Accepted => Ok(probe),
        Spend::Rejected => Err("script ran and rejected the probe value".to_string()),
        Spend::Refused(e) => Err(e),
    }
}

/// 1000 does not fit one byte. The script says so; the mock must too.
#[test]
fn num2bin_refuses_a_width_too_small_for_the_value() {
    let err = script_num2bin_accepts(&BigInt::from(1000), 1)
        .expect_err("the emitted num2bin ACCEPTED 1000 in one byte — this test's premise is gone");
    assert!(
        err.contains("too large for target size"),
        "expected OP_NUM2BIN to fail on the size, got: {err}"
    );

    let mock = std::panic::catch_unwind(|| num2bin(&1000, 1));
    assert!(
        mock.is_err(),
        "MOCK/EMITTER DISAGREE — the emitted num2bin FAILS on num2bin(1000, 1) ({err}), but \
         prelude::num2bin returned {:?}. It used to fill `length` bytes low-first and drop \
         the rest; OP_NUM2BIN has no wrap-around, so those bytes are a value the script can \
         never produce and nothing told the caller.",
        mock.map(|v| hex_of(&v))
    );
}

/// -2^63 does not fit eight bytes, because the sign bit and the top magnitude
/// bit are the SAME bit. Clearing the sign to read the magnitude leaves zero,
/// so `0000000000000080` decodes as 0, not as -2^63. It needs nine.
#[test]
fn num2bin_refuses_min_i64_in_eight_bytes_and_accepts_it_in_nine() {
    let min = BigInt::from(i64::MIN);

    let err = script_num2bin_accepts(&min, 8)
        .expect_err("the emitted num2bin ACCEPTED -2^63 in eight bytes");
    assert!(
        err.contains("too large for target size"),
        "expected OP_NUM2BIN to fail on the size, got: {err}"
    );

    // Nine bytes is the width that works — settled against the interpreter,
    // not against a second reading of the encoding rule.
    let nine = script_num2bin_accepts(&min, 9)
        .expect("the emitted num2bin REFUSED -2^63 in nine bytes, which is the width it needs");
    assert_eq!(nine.len(), 9);

    let mock = std::panic::catch_unwind(|| num2bin(&i64::MIN, 8));
    assert!(
        mock.is_err(),
        "MOCK/EMITTER DISAGREE — the emitted num2bin FAILS on num2bin(-2^63, 8) ({err}), but \
         prelude::num2bin returned {:?}. That byte string decodes as 0: the mock set the \
         sign bit on a byte whose top magnitude bit was already set.",
        mock.map(|v| hex_of(&v))
    );

    // And nine bytes must be a width the MOCK accepts, not merely one the
    // script accepts — otherwise `num2bin` could refuse everything and the
    // assertion above would pass for the wrong reason. The bytes it produces
    // must be the ones the SPEND above accepted, which is the agreement claim;
    // a hex literal here would only be a second reading of the encoding rule.
    assert_eq!(
        hex_of(&num2bin(&i64::MIN, 9)),
        hex_of(&nine),
        "prelude::num2bin encodes -2^63 in nine bytes differently from the emitted num2bin, \
         whose output the interpreter accepted above"
    );
}

// ---------------------------------------------------------------------------
// Hashes
// ---------------------------------------------------------------------------

#[test]
fn hash_builtins_agree_with_the_emitter() {
    let msg: Vec<u8> = b"runar mock/emitter agreement".to_vec();
    let state = sha256(b"initial state");
    let block = vec![0x5au8; 64];
    let cv = sha256(b"chaining value");
    reconcile_unrunnable(&run_group(
        "hashes",
        vec![
            bytes_case("sha256", "sha256", vec!["ByteString"], vec![msg.clone()], "Sha256", sha256(&msg)),
            bytes_case(
                "sha256",
                "sha256_hash",
                vec!["ByteString"],
                vec![msg.clone()],
                "Sha256",
                sha256_hash(&msg),
            ),
            bytes_case("hash256", "hash256", vec!["ByteString"], vec![msg.clone()], "Sha256", hash256(&msg)),
            bytes_case(
                "hash160",
                "hash160",
                vec!["ByteString"],
                vec![msg.clone()],
                "Ripemd160",
                hash160(&msg),
            ),
            bytes_case(
                "ripemd160",
                "ripemd160",
                vec!["ByteString"],
                vec![msg.clone()],
                "Ripemd160",
                ripemd160(&msg),
            ),
            bytes_case(
                "blake3Hash",
                "blake3_hash",
                vec!["ByteString"],
                vec![msg.clone()],
                "ByteString",
                blake3_hash(&msg),
            ),
            bytes_case(
                "blake3Compress",
                "blake3_compress",
                vec!["ByteString", "ByteString"],
                vec![cv.clone(), block.clone()],
                "ByteString",
                blake3_compress(&cv, &block),
            ),
            bytes_case(
                "sha256Compress",
                "sha256_compress",
                vec!["ByteString", "ByteString"],
                vec![state.clone(), block.clone()],
                "ByteString",
                sha256_compress(&state, &block),
            ),
            bytes_case(
                "sha256Finalize",
                "sha256_finalize",
                vec!["ByteString", "ByteString", "bigint"],
                vec![state.clone(), vec![1, 2, 3, 4], num_i(1024 + 32)],
                "ByteString",
                sha256_finalize(&state, &[1, 2, 3, 4], 1024 + 32),
            ),
        ],
    ));
}

// ---------------------------------------------------------------------------
// Elliptic curve
// ---------------------------------------------------------------------------

fn ec_point_case(
    builtin: &'static str,
    mock: &'static str,
    arg_tys: Vec<&'static str>,
    args: Vec<Vec<u8>>,
    want: Point,
) -> AgreementCase {
    AgreementCase {
        builtin,
        mock,
        arg_tys,
        args,
        ret_ty: "Point",
        tamper: tamper_bs(&want),
        want,
        call_extra: vec![],
        known_divergent: "",
    }
}

#[test]
fn ec_builtins_agree_with_the_emitter() {
    let p = ec_mul_gen(5);
    let q = ec_mul_gen(9);
    reconcile_unrunnable(&run_group(
        "EC",
        vec![
            ec_point_case(
                "ecAdd",
                "ec_add",
                vec!["Point", "Point"],
                vec![p.clone(), q.clone()],
                ec_add(&p, &q),
            ),
            ec_point_case("ecNegate", "ec_negate", vec!["Point"], vec![p.clone()], ec_negate(&p)),
            AgreementCase {
                builtin: "ecOnCurve",
                mock: "ec_on_curve",
                arg_tys: vec!["Point"],
                args: vec![p.clone()],
                ret_ty: "boolean",
                want: boolean(ec_on_curve(&p)),
                tamper: boolean(!ec_on_curve(&p)),
                call_extra: vec![],
                known_divergent: "",
            },
            bytes_case(
                "ecEncodeCompressed",
                "ec_encode_compressed",
                vec!["Point"],
                vec![p.clone()],
                "ByteString",
                ec_encode_compressed(&p),
            ),
            int_case("ecModReduce", "ec_mod_reduce", ec_mod_reduce(1000003, 97), &[1000003, 97]),
            ec_point_case("ecMulGen", "ec_mul_gen", vec!["bigint"], vec![num_i(5)], ec_mul_gen(5)),
            ec_point_case(
                "ecMul",
                "ec_mul",
                vec!["Point", "bigint"],
                vec![p.clone(), num_i(3)],
                ec_mul(&p, 3),
            ),
        ],
    ));
}

/// A secp256k1 coordinate is 256 bits, so every row here is past 2^63 by
/// construction — which is exactly why `ec_point_x` returning a narrow integer
/// could never have been right, and why a row passing 11 and 22 to
/// `ec_make_point` covers nothing: no curve point has an 8-byte coordinate.
#[test]
fn ec_coordinates_carry_their_full_width() {
    let p = ec_mul_gen(5);
    let x = ec_point_x(&p);
    let y = ec_point_y(&p);
    assert!(
        x.bits() > 64 && y.bits() > 64,
        "5G's coordinates fit 64 bits, so these rows would not exercise width at all"
    );
    reconcile_unrunnable(&run_group(
        "EC coordinates",
        vec![
            AgreementCase {
                builtin: "ecPointX",
                mock: "ec_point_x",
                arg_tys: vec!["Point"],
                args: vec![p.clone()],
                ret_ty: "bigint",
                want: num_b(&x),
                tamper: num_b(&(&x + 1)),
                call_extra: vec![],
                known_divergent: "",
            },
            AgreementCase {
                builtin: "ecPointY",
                mock: "ec_point_y",
                arg_tys: vec!["Point"],
                args: vec![p.clone()],
                ret_ty: "bigint",
                want: num_b(&y),
                tamper: num_b(&(&y + 1)),
                call_extra: vec![],
                known_divergent: "",
            },
            // Rebuilding a real point from its own accessors. This is the
            // identity `examples/rust/ec-unit` asserts in its contract and
            // could not run: the contract was excluded from native compilation
            // entirely, so `assert!(ec_on_curve(rebuilt))` had never executed
            // off-chain in any form.
            AgreementCase {
                builtin: "ecMakePoint",
                mock: "ec_make_point (real coordinates)",
                arg_tys: vec!["bigint", "bigint"],
                args: vec![num_b(&x), num_b(&y)],
                ret_ty: "Point",
                tamper: tamper_bs(&ec_make_point(x.clone(), y.clone())),
                want: ec_make_point(x.clone(), y.clone()),
                call_extra: vec![],
                known_divergent: "",
            },
        ],
    ));

    // The accessors must round-trip to the point they came from. Without this,
    // ec_point_x and ec_make_point could both be wrong in compensating ways —
    // each row above only pins one direction against the script.
    assert_eq!(ec_make_point(x, y), p, "ec_make_point did not rebuild 5G from its own coordinates");
}

// ---------------------------------------------------------------------------
// The interpreter's own limit, pinned rather than assumed
// ---------------------------------------------------------------------------

/// `UNRUNNABLE` above rests on a claim about `bsv-sdk`: that it refuses OP_2MUL
/// unconditionally. That claim is the reason three EC rows are excused, so it
/// has to be CHECKED rather than asserted in a comment — otherwise the excuse
/// outlives the limitation and three rows stay silently uncovered.
///
/// It also scopes the Rust tier's `ScriptVm` far more widely than the EC rows
/// suggest: `compilers/rust/src/codegen/{ec,p256_p384,bn254,koalabear}.rs` all
/// emit OP_2MUL, so `ScriptVm::execute` cannot run ANY contract using those
/// families and reports `success: false` for a script the network would accept.
#[test]
fn the_interpreter_refuses_op_2mul_which_is_why_three_ec_rows_are_excused() {
    // OP_1 OP_2MUL OP_1 — would leave a truthy clean stack if OP_2MUL ran.
    let lock = vec![0x51u8, 0x8d, 0x51];
    let res = ScriptVm::new(VmOptions::default()).execute(&[], &lock);
    assert!(!res.success);
    assert_eq!(
        res.error.as_deref(),
        Some("DisabledOpcode(\"OP_2MUL\")"),
        "bsv-sdk no longer refuses OP_2MUL. The UNRUNNABLE list above exists only \
         because it did: re-run those three EC rows, and if they now execute, take \
         them off the list — an excuse that outlives its reason is how coverage \
         quietly disappears."
    );

    // And the control: a script the interpreter WILL run, so the assertion above
    // is about OP_2MUL and not about `execute` refusing everything.
    let ok = ScriptVm::new(VmOptions::default()).execute(&[], &[0x51u8]);
    assert!(ok.success, "the interpreter rejected OP_1; nothing here proves anything");
}
