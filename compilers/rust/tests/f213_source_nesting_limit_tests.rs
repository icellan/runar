//! F-213 (CL-BUG-172): a nesting bound for Rúnar source, on all nine surfaces.
//!
//! `MAX_SOURCE_BYTES` never bounded recursion: ~2,000 nested parentheses (a
//! 4 KB file) SIGABRTed this tier's release CLI on seven of nine surfaces, and
//! a long `a + a + …` chain aborted even `--parse-only`, because Rust drops a
//! `Box<Expression>` tree recursively. The shared rule (TS reference:
//! packages/runar-compiler/src/passes/source-limits.ts) refuses a source with
//! "source nesting depth exceeds MAX_SOURCE_NESTING (limit=128)" when either
//! (A) the parse-nesting counter or (B) the AST nesting of the finished tree
//! passes 128.
//!
//! The sources are the coordinator's canonical shapes (method top-level
//! statement `result = <expr>`): n nested parens (A = n + 2), n nested `if`s
//! (A = n + 2), n nested `-(` (A = 2n + 2), a k-term `value + value + …` chain
//! (B = k + 1).
//!
//! What these tests prove, per surface: the at-limit source (parens 126,
//! nested-if 126, unary 63, chain 127) is accepted and compiles to the same
//! script as every other surface (parens-126 and unary-63 are pinned to the
//! TS reference's hex); the one-past source (127 / 127 / 64 / 128) is refused
//! with the shared diagnostic; and the deep sources (20,000 levels of each
//! shape, and a 500,000-term chain) are refused with the shared diagnostic by the
//! debug CLI, in a subprocess, with an ordinary non-zero exit and no signal.
//!
//! The .runar.ts surface, parsed by swc, additionally gets a set of guard
//! probes (shapes swc nests by recursion or builds in a loop) that must be
//! refused the same way.
//!
//! What they do NOT prove: that no other shape can exhaust the stack (the
//! deep cases are the four canonical shapes plus the swc probes; wider fuzzing
//! is in remediation-logs/F-213/rust/), byte parity with the other tiers beyond
//! the two pinned hexes (`python3 remediation-logs/F-213/check_tier.py rust`
//! checks every hex against the TS tier), or anything about the release
//! build's stack (the F-213 report measures that separately).

use std::process::Command;

use runar_compiler_rust::compile_from_source_str;
use runar_compiler_rust::frontend::input_limits::{MAX_SOURCE_BYTES, MAX_SOURCE_NESTING};
use runar_compiler_rust::frontend::parser::parse_source;

const DIAG: &str = "source nesting depth exceeds MAX_SOURCE_NESTING (limit=128)";

/// The TS reference's hex for parens-126 and unary-63 (identical on all nine
/// surfaces; remediation-logs/F-213/ts-hex.json).
const PARENS_126_HEX: &str = "767600877c51879b69007b00a07777";
const NEG_63_HEX: &str = "767600877c51879b69007b8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f8f00a07777";

const SURFACES: &[&str] = &["ts", "sol", "move", "go", "rs", "py", "zig", "rb", "java"];

#[derive(Clone, Copy, Debug)]
enum Shape {
    Parens,
    If,
    Neg,
    Chain,
}

/// Per-surface source with `{BODY}` in the method body, the assignment
/// statement, and the nested-if wrapper. Mirrors remediation-logs/F-213/gen.py.
fn template(ext: &str) -> &'static str {
    match ext {
        "ts" => "import { SmartContract, assert } from 'runar-lang';\n\nclass P extends SmartContract {\n  readonly limit: bigint;\n  constructor(limit: bigint) { super(limit); this.limit = limit; }\n  public check(value: bigint, mode: boolean): void {\n    let result: bigint = 0n;\n{BODY}\n    assert(result > 0n);\n  }\n}\n",
        "sol" => "pragma runar ^0.1.0;\n\ncontract P is SmartContract {\n    int immutable limit;\n    constructor(int _limit) { limit = _limit; }\n    function check(int value, bool mode) public {\n        int result = 0;\n{BODY}\n        require(result > 0);\n    }\n}\n",
        "move" => "module P {\n    use runar::types::{Int};\n    struct P { limit: Int, }\n    public fun check(contract: &P, value: Int, mode: bool) {\n        let result: Int = 0;\n{BODY}\n        assert!(result > 0, 0);\n    }\n}\n",
        "go" => "package contract\n\nimport runar \"github.com/icellan/runar/packages/runar-go\"\n\ntype P struct {\n\trunar.SmartContract\n\tLimit runar.Int `runar:\"readonly\"`\n}\n\nfunc (c *P) Check(value runar.Int, mode runar.Bool) {\n\tresult := runar.Int(0)\n{BODY}\n\trunar.Assert(result > 0)\n}\n",
        "rs" => "use runar::prelude::*;\n\n#[runar::contract]\nstruct P {\n    #[readonly]\n    limit: Int,\n}\n\nimpl P {\n    pub fn check(&self, value: Int, mode: bool) {\n        let mut result: Int = 0;\n{BODY}\n        assert!(result > 0);\n    }\n}\n",
        "py" => "from runar import SmartContract, Bigint, public, assert_\n\nclass P(SmartContract):\n    limit: Bigint\n\n    def __init__(self, limit: Bigint):\n        super().__init__(limit)\n        self.limit = limit\n\n    @public\n    def check(self, value: Bigint, mode: bool):\n        result: Bigint = 0\n{BODY}\n        assert_(result > 0)\n",
        "zig" => "const runar = @import(\"runar\");\n\npub const P = struct {\n    pub const Contract = runar.SmartContract;\n    limit: i64,\n    pub fn init(limit: i64) P { return .{ .limit = limit }; }\n    pub fn check(self: *const P, value: i64, mode: bool) void {\n        var result: i64 = 0;\n{BODY}\n        runar.assert(result > 0);\n    }\n};\n",
        "rb" => "require 'runar'\n\nclass P < Runar::SmartContract\n  prop :limit, Bigint\n\n  def initialize(limit)\n    super(limit)\n    @limit = limit\n  end\n\n  runar_public value: Bigint, mode: Boolean\n  def check(value, mode)\n    result = 0\n{BODY}\n    assert result > 0\n  end\nend\n",
        "java" => "package p;\n\nimport runar.lang.SmartContract;\nimport runar.lang.annotations.Public;\nimport runar.lang.annotations.Readonly;\nimport runar.lang.types.Bigint;\n\nimport static runar.lang.Builtins.assertThat;\n\nclass P extends SmartContract {\n    @Readonly Bigint limit;\n    P(Bigint limit) { super(limit); this.limit = limit; }\n    @Public\n    void check(Bigint value, boolean mode) {\n        Bigint result = Bigint.ZERO;\n{BODY}\n        assertThat(result.gt(Bigint.ZERO));\n    }\n}\n",
        _ => unreachable!("unknown surface {ext}"),
    }
}

fn assign(ext: &str, e: &str) -> String {
    match ext {
        "go" => format!("\tresult = {e}"),
        "py" => format!("        result = {e}"),
        "rb" => format!("    result = {e}"),
        _ => format!("        result = {e};"),
    }
}

fn nested_if(ext: &str, n: usize) -> String {
    let inner = assign(ext, "value").trim().to_string();
    match ext {
        "py" => {
            let mut lines: Vec<String> =
                (0..n).map(|i| format!("        {}if mode:", " ".repeat(i))).collect();
            lines.push(format!("        {}{inner}", " ".repeat(n)));
            lines.join("\n")
        }
        "rb" => format!("{}{inner}\n{}", "if mode\n".repeat(n), "end\n".repeat(n)),
        "move" => format!("{}{inner}\n{}", "if (mode) {\n".repeat(n), "};\n".repeat(n)),
        "go" | "rs" => format!("{}{inner}\n{}", "if mode {\n".repeat(n), "}\n".repeat(n)),
        _ => format!("{}{inner}\n{}", "if (mode) {\n".repeat(n), "}\n".repeat(n)),
    }
}

fn source(ext: &str, shape: Shape, n: usize) -> String {
    let body = match shape {
        Shape::Parens => assign(ext, &format!("{}value{}", "(".repeat(n), ")".repeat(n))),
        Shape::Neg => assign(ext, &format!("{}value{}", "-(".repeat(n), ")".repeat(n))),
        Shape::Chain => assign(ext, &vec!["value"; n].join(" + ")),
        Shape::If => nested_if(ext, n),
    };
    template(ext).replace("{BODY}", &body)
}

fn file_name(ext: &str) -> String {
    format!("P.runar.{ext}")
}

/// Every parser runs on its own 64 MiB stack segment, but the passes after it
/// (validate, typecheck, ANF lowering, ...) walk an at-limit program (~130
/// nested statements or expressions) on the caller's stack. Measured on the
/// CLI (remediation-logs/F-213/rust/ulimit-*.txt): a release build compiles
/// every at-limit source on a 512 KiB stack; a DEBUG build -- what `cargo
/// test` runs -- needs between 1 and 2 MiB for nested-if-126, under 2x margin
/// against cargo's 2 MiB test threads. So the in-process compiles run on a
/// thread with an explicit 8 MiB stack: the tests measure the limit, not the
/// debug frame size of a given platform.
fn on_big_stack<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    std::thread::Builder::new()
        .stack_size(8 * 1024 * 1024)
        .spawn(f)
        .expect("spawn")
        .join()
        .expect("join")
}

fn compile_hex(ext: &str, shape: Shape, n: usize) -> Result<String, String> {
    let src = source(ext, shape, n);
    let name = file_name(ext);
    on_big_stack(move || compile_from_source_str(&src, Some(&name)).map(|a| a.script))
}

fn refusal(ext: &str, shape: Shape, n: usize) -> Option<String> {
    let src = source(ext, shape, n);
    let name = file_name(ext);
    on_big_stack(move || {
        let res = parse_source(&src, Some(&name));
        res.errors.iter().map(|d| d.format_message()).find(|m| m.contains(DIAG))
    })
}

#[test]
fn the_limit_is_128_and_the_message_is_shared() {
    assert_eq!(MAX_SOURCE_NESTING, 128);
    assert_eq!(
        runar_compiler_rust::frontend::input_limits::SOURCE_NESTING_MESSAGE,
        format!("source nesting depth exceeds MAX_SOURCE_NESTING (limit={MAX_SOURCE_NESTING})"),
    );
    assert_eq!(runar_compiler_rust::frontend::input_limits::SOURCE_NESTING_MESSAGE, DIAG);
}

/// Collect every surface's failure before failing, so a run shows all nine.
fn check_all(what: &str, mut case: impl FnMut(&str) -> Result<(), String>) {
    let failures: Vec<String> = SURFACES.iter().filter_map(|ext| case(ext).err()).collect();
    assert!(failures.is_empty(), "{what}: {} of {} surfaces failed:\n  {}", failures.len(), SURFACES.len(), failures.join("\n  "));
}

fn expect_hex(ext: &str, shape: Shape, n: usize, want: &str) -> Result<(), String> {
    match compile_hex(ext, shape, n) {
        Ok(hex) if hex == want => Ok(()),
        Ok(hex) => Err(format!("{ext}: {shape:?}-{n} compiled to {hex}, want {want}")),
        Err(e) => Err(format!("{ext}: {shape:?}-{n} refused: {}", e.chars().take(200).collect::<String>())),
    }
}

fn expect_refused(ext: &str, shape: Shape, n: usize) -> Result<(), String> {
    match refusal(ext, shape, n) {
        Some(_) => Ok(()),
        None => Err(format!("{ext}: {shape:?}-{n} not refused with the shared diagnostic")),
    }
}

#[test]
fn at_limit_parens_are_accepted_on_every_surface() {
    check_all("parens-126", |ext| expect_hex(ext, Shape::Parens, MAX_SOURCE_NESTING - 2, PARENS_126_HEX));
}

#[test]
fn one_past_limit_parens_are_refused_on_every_surface() {
    check_all("parens-127", |ext| expect_refused(ext, Shape::Parens, MAX_SOURCE_NESTING - 1));
}

#[test]
fn at_limit_nested_if_is_accepted_on_every_surface() {
    let reference = compile_hex("ts", Shape::If, MAX_SOURCE_NESTING - 2).expect("ts if-126");
    check_all("if-126", |ext| expect_hex(ext, Shape::If, MAX_SOURCE_NESTING - 2, &reference));
}

#[test]
fn one_past_limit_nested_if_is_refused_on_every_surface() {
    check_all("if-127", |ext| expect_refused(ext, Shape::If, MAX_SOURCE_NESTING - 1));
}

#[test]
fn unary_boundary_matches_the_reference_on_every_surface() {
    let n = (MAX_SOURCE_NESTING - 2) / 2;
    check_all("neg-63", |ext| expect_hex(ext, Shape::Neg, n, NEG_63_HEX));
    check_all("neg-64", |ext| expect_refused(ext, Shape::Neg, n + 1));
}

#[test]
fn chain_boundary_matches_the_reference_on_every_surface() {
    let reference = compile_hex("ts", Shape::Chain, MAX_SOURCE_NESTING - 1).expect("ts chain-127");
    check_all("chain-127", |ext| expect_hex(ext, Shape::Chain, MAX_SOURCE_NESTING - 1, &reference));
    check_all("chain-128", |ext| expect_refused(ext, Shape::Chain, MAX_SOURCE_NESTING));
}

/// Run the debug CLI on `src` in a subprocess: a stack overflow there is a
/// signal the test can observe instead of an abort of the test binary.
fn cli_outcome(src: &str, ext: &str, tag: &str) -> (Option<i32>, String) {
    let dir = std::env::temp_dir().join(format!("f213-{}-{}-{}", std::process::id(), ext, tag));
    std::fs::create_dir_all(&dir).expect("mkdir");
    let path = dir.join(file_name(ext));
    std::fs::write(&path, src).expect("write source");
    let out = Command::new(env!("CARGO_BIN_EXE_runar-compiler-rust"))
        .arg("--source")
        .arg(&path)
        .arg("--hex")
        .output()
        .expect("run CLI");
    let _ = std::fs::remove_dir_all(&dir);
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code(), text)
}

fn cli_refuses(src: &str, ext: &str, tag: &str) -> Result<(), String> {
    if src.len() > MAX_SOURCE_BYTES {
        return Err(format!("{ext} {tag}: probe exceeds MAX_SOURCE_BYTES"));
    }
    let (code, text) = cli_outcome(src, ext, tag);
    let head: String = text.chars().take(200).collect::<String>().replace('\n', " ");
    // `code` is None when the process died by a signal (SIGABRT on overflow).
    match code {
        Some(c) if c != 0 && text.contains(DIAG) => Ok(()),
        Some(c) if c != 0 => Err(format!("{ext} {tag}: exit {c} without the shared diagnostic: {head}")),
        _ => Err(format!("{ext} {tag}: expected an ordinary non-zero exit, got {code:?}: {head}")),
    }
}

#[test]
fn deep_parens_are_refused_without_a_crash_on_every_surface() {
    check_all("parens-20000", |ext| cli_refuses(&source(ext, Shape::Parens, 20_000), ext, "parens-20000"));
}

#[test]
fn deep_nested_if_is_refused_without_a_crash_on_every_surface() {
    // 20,000 levels of Python indentation exceed MAX_SOURCE_BYTES.
    check_all("if-deep", |ext| {
        let n = if ext == "py" { 2_500 } else { 20_000 };
        cli_refuses(&source(ext, Shape::If, n), ext, "if-deep")
    });
}

#[test]
fn deep_unary_is_refused_without_a_crash_on_every_surface() {
    check_all("neg-20000", |ext| cli_refuses(&source(ext, Shape::Neg, 20_000), ext, "neg-20000"));
}

#[test]
fn deep_chain_is_refused_without_a_crash_on_every_surface() {
    check_all("chain-20000", |ext| cli_refuses(&source(ext, Shape::Chain, 20_000), ext, "chain-20000"));
}

#[test]
fn half_million_term_chain_is_refused_without_a_crash_on_every_surface() {
    check_all("chain-500000", |ext| cli_refuses(&source(ext, Shape::Chain, 500_000), ext, "chain-500000"));
}

/// The .runar.ts surface is parsed by swc, whose recursion this tier cannot
/// count; a token guard in front of swc stops a source whose AST would get too
/// deep (src/frontend/ts_nesting.rs). Each probe is a shape swc nests by
/// recursion or builds in a loop -- including the else-if chain and the
/// dangling-else chain swc builds iteratively, a regex that hides a backquote
/// from a naive scanner, and a deep expression outside the contract class --
/// and must be refused with the shared diagnostic, with no signal.
#[test]
fn swc_guard_probes_are_refused_without_a_crash() {
    let wrap = |body: &str, top: &str| {
        template("ts").replace("import { SmartContract, assert } from 'runar-lang';\n", &format!("import {{ SmartContract, assert }} from 'runar-lang';\n{top}\n")).replace("{BODY}", body)
    };
    let expr = |e: String| wrap(&format!("    result = {e};"), "");
    let n = 20_000;
    let probes: Vec<(&str, String)> = vec![
        ("member-chain", expr(format!("value{}", ".a".repeat(200_000)))),
        ("non-null-chain", expr(format!("value{}", "!".repeat(500_000)))),
        ("call-chain", expr(format!("value{}", "()".repeat(200_000)))),
        ("group-chain", expr(vec!["(value)"; 200_000].join(" + "))),
        ("tagged-template-chain", expr(format!("value{}", "`x`".repeat(200_000)))),
        ("ternary-chain", expr(format!("{}value", "mode ? value : ".repeat(50_000)))),
        ("bang-prefix", expr(format!("{}value", "!".repeat(500_000)))),
        ("typeof-prefix", expr(format!("{}value", "typeof ".repeat(100_000)))),
        ("array-nest", expr(format!("{}{}", "[".repeat(n), "]".repeat(n)))),
        ("object-nest", expr(format!("{}1{}", "{a:".repeat(n), "}".repeat(n)))),
        ("template-nest", expr(format!("{}1{}", "`${".repeat(n), "}`".repeat(n)))),
        ("regex-hides-backquote", expr(format!("/[`]/ + {}value{}", "(".repeat(n), ")".repeat(n)))),
        ("braceless-if", wrap(&format!("{}result = value;", "if (mode) ".repeat(n)), "")),
        ("else-if-chain", wrap(&format!("if (mode) {{}}{}", " else if (mode) {}".repeat(n)), "")),
        ("dangling-else", wrap(&format!("{}result = value;", "if (mode) result = value; else ".repeat(n)), "")),
        ("top-level-parens", wrap("", &format!("const z = {}1{};", "(".repeat(n), ")".repeat(n)))),
        ("top-level-chain", wrap("", &format!("const z = {};", vec!["1"; 200_000].join(" + ")))),
        ("type-generic", wrap("", &format!("type T = {}bigint{};", "FixedArray<".repeat(n), ", 1>".repeat(n)))),
        ("type-array", wrap("", &format!("type T = bigint{};", "[]".repeat(500_000)))),
    ];
    let failures: Vec<String> =
        probes.iter().filter_map(|(tag, src)| cli_refuses(src, "ts", tag).err()).collect();
    assert!(failures.is_empty(), "{} swc probes failed:\n  {}", failures.len(), failures.join("\n  "));
}
