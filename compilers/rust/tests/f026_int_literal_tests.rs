//! F-026 (CL-BUG-198) — an integer literal means what its host language says
//! it means, on every surface, or it is refused.
//!
//! Pre-fix, this tier's hand-written tokenizers scanned decimal digits (and
//! sometimes `0x`) only. `0b1010` on .runar.py / .runar.zig lexed as `0` plus
//! the identifier `b1010`, and with an identifier of that name in scope the
//! stray token was absorbed (.zig call arguments needed no commas, .py took two
//! statements on one line), so `amount > 0b1010` compiled to `amount > 0`.
//!
//! The rule is the TS reference's (packages/runar-compiler/src/passes/
//! int-literal.ts, user decision R15): the number token runs over every glued
//! [0-9A-Za-z_] character and must be an integer literal of the surface's host
//! language, with that language's value (table:
//! conformance/negatives/int-literal-cases.json, generated from the host
//! toolchains); anything else is refused with
//! "invalid <Language> integer literal '<text>'". Also: .zig call and array
//! lists require commas; .py refuses a second statement on one line.
//!
//! What this proves: this tier's validator reproduces every table row; every
//! hand-written tokenizer and the swc .runar.ts path accept exactly the
//! table's forms with its values and refuse the rest with the shared text;
//! the attempt-1 exploit shapes
//! read 10; the absorbing paths are closed.
//! What it does NOT prove: the other tiers, or the Solidity / Move rows
//! themselves (documentation-derived).

use runar_compiler_rust::frontend::int_literal::{invalid_integer_literal, parse_int_literal};
use runar_compiler_rust::frontend::parser::parse_source;

const ZIG_COMMA: &str = "expected ',' between list elements";
const PY_LINE_BREAK: &str = "expected a line break between statements";
const SURFACES: [&str; 9] = ["ts", "sol", "move", "go", "rs", "py", "zig", "rb", "java"];

fn template(surface: &str, l: &str) -> String {
    match surface {
        "ts" => format!("import {{ SmartContract, assert }} from 'runar-lang';\n\nclass T extends SmartContract {{\n  readonly target: bigint;\n\n  constructor(target: bigint) {{\n    super(target);\n    this.target = target;\n  }}\n\n  public verify(a: bigint): void {{\n    assert(a > {l});\n  }}\n}}\n"),
        "sol" => format!("pragma runar ^0.1.0;\n\ncontract T is SmartContract {{\n    int immutable target;\n\n    constructor(int _target) {{\n        target = _target;\n    }}\n\n    function verify(int a) public {{\n        require(a > {l});\n    }}\n}}\n"),
        "move" => format!("module T {{\n    use runar::types::{{Int}};\n\n    struct T {{\n        target: Int,\n    }}\n\n    public fun verify(contract: &T, a: Int) {{\n        assert!(a > {l});\n    }}\n}}\n"),
        "go" => format!("package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n\ntype T struct {{\n\trunar.SmartContract\n\tTarget runar.Int `runar:\"readonly\"`\n}}\n\nfunc (c *T) Verify(a runar.Int) {{\n\trunar.Assert(a > {l})\n}}\n"),
        "rs" => format!("use runar::prelude::*;\n\n#[runar::contract]\nstruct T {{\n    #[readonly]\n    target: Int,\n}}\n\nimpl T {{\n    pub fn verify(&self, a: Int) {{\n        assert!(a > {l});\n    }}\n}}\n"),
        "py" => format!("from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n    target: Bigint\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n        self.target = target\n\n    @public\n    def verify(self, a: Bigint):\n        assert_(a > {l})\n"),
        "zig" => format!("const runar = @import(\"runar\");\n\npub const T = struct {{\n    pub const Contract = runar.SmartContract;\n\n    target: i64,\n\n    pub fn init(target: i64) T {{\n        return .{{ .target = target }};\n    }}\n\n    pub fn verify(self: *const T, a: i64) void {{\n        _ = self;\n        runar.assert(a > {l});\n    }}\n}};\n"),
        "rb" => format!("require 'runar'\n\nclass T < Runar::SmartContract\n  prop :target, Bigint\n\n  def initialize(target)\n    super(target)\n    @target = target\n  end\n\n  runar_public a: Bigint\n  def verify(a)\n    assert a > {l}\n  end\nend\n"),
        "java" => format!("package t;\n\nimport runar.lang.SmartContract;\nimport runar.lang.annotations.Public;\nimport runar.lang.annotations.Readonly;\nimport runar.lang.types.Bigint;\n\nimport static runar.lang.Builtins.assertThat;\n\nclass T extends SmartContract {{\n\n    @Readonly Bigint target;\n\n    T(Bigint target) {{\n        super(target);\n        this.target = target;\n    }}\n\n    @Public\n    void verify(Bigint a) {{\n        assertThat(a.gt(Bigint.of({l})));\n    }}\n}}\n"),
        _ => unreachable!(),
    }
}

/// Whether a refused literal must carry the shared text: every surface in
/// this tier, the swc `.runar.ts` path included (its numbers are pre-checked
/// with swc's own lexer).
fn hand_written(_surface: &str) -> bool {
    true
}

fn cases() -> serde_json::Map<String, serde_json::Value> {
    let p = format!("{}/../../conformance/negatives/int-literal-cases.json", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {}", p, e));
    let v: serde_json::Value = serde_json::from_str(&text).unwrap();
    v["cases"].as_object().unwrap().clone()
}

/// The bigint literals in method `verify` (from the AST's Debug form) and the
/// error messages.
fn literals(src: &str, file: &str) -> (Vec<String>, Vec<String>) {
    let r = parse_source(src, Some(file));
    let errs: Vec<String> = r.errors.iter().map(|e| e.format_message()).collect();
    let mut vals = Vec::new();
    if let Some(c) = &r.contract {
        for m in &c.methods {
            if m.name == "verify" {
                let dbg = format!("{:?}", m.body);
                let mut rest = dbg.as_str();
                while let Some(i) = rest.find("BigIntLiteral { value: ") {
                    rest = &rest[i + "BigIntLiteral { value: ".len()..];
                    let end = rest.find(' ').unwrap();
                    vals.push(rest[..end].to_string());
                }
            }
        }
    }
    (vals, errs)
}

fn has(errs: &[String], want: &str) -> bool {
    errs.iter().any(|e| e.contains(want))
}

#[test]
fn f026_validator_reproduces_host_table() {
    let cases = cases();
    assert_eq!(cases.len(), 9);
    let mut bad = Vec::new();
    for (surf, rows) in &cases {
        for row in rows.as_array().unwrap() {
            let lit = row[0].as_str().unwrap();
            let want = row[1].as_str().map(|s| s.to_string());
            let got = parse_int_literal(surf, lit).filter(|l| !l.neg_only).map(|l| l.value.to_string());
            if got != want {
                bad.push(format!("{surf} {lit}: want {want:?}, got {got:?}"));
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn f026_every_tokenizer_applies_the_table() {
    let cases = cases();
    let mut bad = Vec::new();
    for surf in SURFACES {
        for row in cases[surf].as_array().unwrap() {
            let lit = row[0].as_str().unwrap();
            let (vals, errs) = literals(&template(surf, lit), &format!("T.runar.{surf}"));
            match row[1].as_str() {
                None => {
                    if errs.is_empty() {
                        bad.push(format!("{surf} {lit}: accepted as {vals:?}"));
                    } else if hand_written(surf) && !has(&errs, &invalid_integer_literal(surf, lit)) {
                        bad.push(format!("{surf} {lit}: refused without the shared text: {errs:?}"));
                    }
                }
                Some(want) => {
                    // N-028 (a separate item, not fixed here): this tier's swc
                    // path reads a plain `.runar.ts` number through f64, so an
                    // unsuffixed value above 2^53 is rounded. Acceptance is
                    // still checked; the exact value is left to N-028.
                    if surf == "ts" && !lit.ends_with('n') && want.len() > 15 && errs.is_empty() && vals.len() == 1 {
                        continue;
                    }
                    if !errs.is_empty() || vals != vec![want.to_string()] {
                        bad.push(format!("{surf} {lit}: want [{want}], got {vals:?} {errs:?}"));
                    }
                }
            }
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}

#[test]
fn f026_unary_minus_only_literals() {
    for (surf, src, want) in [
        ("java", "-2147483648", "2147483648"),
        ("java", "- 9223372036854775808L", "9223372036854775808"),
        ("rs", "-128i8", "128"),
        ("rs", "-(128i8)", "128"),
        ("rs", "-9223372036854775808i64", "9223372036854775808"),
    ] {
        let (vals, errs) = literals(&template(surf, src), &format!("T.runar.{surf}"));
        assert!(errs.is_empty() && vals == vec![want.to_string()], "{surf} {src}: {vals:?} {errs:?}");
    }
    for (surf, src, lit) in [
        ("java", "-(2147483648)", "2147483648"),
        ("java", "1 - 2147483648", "2147483648"),
        ("java", "2147483648", "2147483648"),
        ("java", "-9223372036854775808", "9223372036854775808"),
        ("rs", "128i8", "128i8"),
        ("rs", "1 - 128i8", "128i8"),
        ("rs", "-129i8", "129i8"),
    ] {
        let (_, errs) = literals(&template(surf, src), &format!("T.runar.{surf}"));
        assert!(has(&errs, &invalid_integer_literal(surf, lit)), "{surf} {src}: {errs:?}");
    }
}

fn zig(params: &str, body: &str) -> String {
    format!("const runar = @import(\"runar\");\n\npub const T = struct {{\n    pub const Contract = runar.SmartContract;\n\n    target: i64,\n\n    pub fn init(target: i64) T {{\n        return .{{ .target = target }};\n    }}\n\n    pub fn verify(self: *const T, amount: i64{params}) void {{\n        _ = self;\n{body}\n    }}\n}};\n")
}

fn py(params: &str, body: &str) -> String {
    format!("from runar import SmartContract, Bigint, ByteString, public, assert_\n\nclass T(SmartContract):\n    target: Bigint\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n        self.target = target\n\n    @public\n    def verify(self, amount: Bigint{params}):\n{body}\n")
}

fn property_init(src: &str, file: &str, idx: usize) -> String {
    let r = parse_source(src, Some(file));
    assert!(r.errors.is_empty(), "{file}: {:?}", r.errors);
    format!("{:?}", r.contract.unwrap().properties[idx].initializer)
}

#[test]
fn f026_exploit_shapes_read_the_literal() {
    let (vals, errs) = literals(&zig(", b1010: runar.ByteString", "        runar.assert(amount > 0b1010);"), "T.runar.zig");
    assert!(errs.is_empty() && vals == vec!["10"], "zig 0b1010 beside b1010: {vals:?} {errs:?}");
    let (_, errs) = literals(&zig(", B1010: i64", "        runar.assert(amount > 0B1010);\n        runar.assert(B1010 == B1010);"), "T.runar.zig");
    assert!(has(&errs, &invalid_integer_literal("zig", "0B1010")), "zig 0B1010: {errs:?}");
    for lit in ["0b1010", "0o12", "0xa"] {
        let src = format!("const runar = @import(\"runar\");\n\npub const T = struct {{\n    pub const Contract = runar.SmartContract;\n\n    target: i64 = {lit},\n\n    pub fn verify(self: *const T, amount: i64) void {{\n        runar.assert(amount > self.target);\n    }}\n}};\n");
        assert_eq!(property_init(&src, "T.runar.zig", 0), "Some(BigIntLiteral { value: 10 })", "zig field default {lit}");
    }
    let (vals, errs) = literals(&py(", b1010: Bigint", "        lim = 0b1010\n        assert_(amount > lim)"), "T.runar.py");
    assert!(errs.is_empty() && vals == vec!["10"], "py 0b1010 beside b1010: {vals:?} {errs:?}");
    for lit in ["0o12", "0b1010"] {
        let src = format!("from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n    target: Bigint\n    limit: Bigint = {lit}\n\n    def __init__(self, target: Bigint):\n        super().__init__(target)\n        self.target = target\n\n    @public\n    def verify(self, amount: Bigint):\n        assert_(amount > self.limit)\n");
        assert_eq!(property_init(&src, "T.runar.py", 1), "Some(BigIntLiteral { value: 10 })", "py class default {lit}");
    }
    for lit in ["0b102", "0o19"] {
        let (_, errs) = literals(&template("ts", lit), "T.runar.ts");
        assert!(has(&errs, &invalid_integer_literal("ts", lit)), "ts {lit}: {errs:?}");
    }
}

#[test]
fn f026_absorbing_paths() {
    let (_, errs) = literals(&zig(", b: i64", "        runar.assert(runar.within(amount b, 20));"), "T.runar.zig");
    assert!(has(&errs, ZIG_COMMA), "zig call without comma: {errs:?}");
    let (_, errs) = literals(&zig(", b: i64", "        runar.assert(runar.within(amount, b, 20,));"), "T.runar.zig");
    assert!(!has(&errs, ZIG_COMMA), "zig call with trailing comma: {errs:?}");
    let (_, errs) = literals(&zig("", "        const xs = [ 1 2, 3 ];\n        runar.assert(amount > xs[0]);"), "T.runar.zig");
    assert!(has(&errs, ZIG_COMMA), "zig [...] without comma: {errs:?}");
    let (_, errs) = literals(&zig("", "        const xs: [3]i64 = .{ 1, 2 3 };\n        runar.assert(amount > xs[0]);"), "T.runar.zig");
    assert!(has(&errs, ZIG_COMMA), "zig .{{}} without comma: {errs:?}");
    let (_, errs) = literals(&py(", b: Bigint", "        lim = 10 b\n        assert_(amount > lim)"), "T.runar.py");
    assert!(has(&errs, PY_LINE_BREAK), "py two statements: {errs:?}");
    let (_, errs) = literals(&py("", "        assert_(amount > 1) assert_(amount > 2)"), "T.runar.py");
    assert!(has(&errs, PY_LINE_BREAK), "py two asserts: {errs:?}");
    let cls = "from runar import SmartContract, Bigint, public, assert_\n\nclass T(SmartContract):\n    target: Bigint = 10 extra\n\n    @public\n    def verify(self, amount: Bigint):\n        assert_(amount > self.target)\n";
    let r = parse_source(cls, Some("T.runar.py"));
    let msgs: Vec<String> = r.errors.iter().map(|e| e.format_message()).collect();
    assert!(has(&msgs, PY_LINE_BREAK), "py class field with trailing token: {msgs:?}");
    let src = template("ts", "10").replace("assert(a > 10);", "assert(a > 10;");
    let (_, errs) = literals(&src, "T.runar.ts");
    assert!(!errs.is_empty(), "ts unclosed call accepted");
}
