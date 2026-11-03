//! F-011 (CL-BUG-196) — an unterminated string or byte-string literal is
//! refused, never scanned onward into the lines that follow it.
//!
//! Pre-fix, this tier's .runar.py tokenizer ended an unterminated literal at
//! the line break silently and skipped every line after an unclosed
//! docstring, which dropped the guard in N54 (the emitted script had no
//! `y < 5` check). Its .runar.java tokenizer read a char literal as a string,
//! and its run-to-next-quote tokenizers (.sol/.move/.zig/.java/.go) swallowed
//! the next line into the literal.
//!
//! The rule is the TS reference's (packages/runar-compiler/src/errors.ts,
//! UNTERMINATED_STRING_LITERAL): a quoted literal that reaches a line break or
//! end of file before its closing quote is refused with exactly
//! "unterminated string literal" at its opening quote; on .runar.rs, for
//! Python triple-quoted strings and for .runar.go backtick raw strings only
//! end of file counts; a Java char literal is refused with
//! "char literals are unsupported in Rúnar Java contracts".
//!
//! What this proves: every hand-written surface of this tier refuses the
//! conformance negatives N52-N63 with that exact text at the opening quote's
//! line; the closed-literal controls, Python docstrings and a Rust string that
//! spans lines are not refused for it; .runar.ts (swc) still refuses N64.
//! What it does NOT prove: anything about the other tiers (their suites and
//! conformance/negatives/rejection-parity.test.ts), or literal forms the
//! hand-written tokenizers never scanned (raw strings, heredocs, text blocks).

use runar_compiler_rust::frontend::parser::parse_source;

const MSG: &str = "unterminated string literal";
const CHAR_MSG: &str = "char literals are unsupported in Rúnar Java contracts";

struct Fx {
    file: &'static str,
    line: usize,
    open: &'static str,
    closed: &'static str,
    msg: &'static str, // "" = not hand-written in this tier
}

const FIXTURES: &[Fx] = &[
    Fx { file: "N52-py-bytes-unterminated-swallow.runar.py", line: 22, open: "b\"cafe\n", closed: "b\"cafe\"\n", msg: MSG },
    Fx { file: "N53-py-string-unterminated.runar.py", line: 13, open: "'cafe\n", closed: "'cafe'\n", msg: MSG },
    Fx { file: "N54-py-docstring-unterminated.runar.py", line: 19, open: "follows.\n", closed: "follows.\"\"\"\n", msg: MSG },
    Fx { file: "N55-sol-string-unterminated.runar.sol", line: 13, open: "\"cafe\n", closed: "\"cafe\";\n", msg: MSG },
    Fx { file: "N56-move-string-unterminated.runar.move", line: 12, open: "\"cafe\n", closed: "\"cafe\";\n", msg: MSG },
    Fx { file: "N57-zig-string-unterminated.runar.zig", line: 12, open: "\"cafe\n", closed: "\"cafe\";\n", msg: MSG },
    Fx { file: "N58-rs-string-unterminated.runar.rs", line: 13, open: "\"cafe;\n", closed: "\"cafe\";\n", msg: MSG },
    Fx { file: "N59-java-string-unterminated.runar.java", line: 22, open: "\"cafe\n", closed: "\"cafe\");\n", msg: MSG },
    Fx { file: "N60-java-char-literal.runar.java", line: 21, open: "", closed: "", msg: CHAR_MSG },
    Fx { file: "N61-rb-single-quote-unterminated.runar.rb", line: 10, open: "'cafe\n", closed: "'cafe'\n", msg: MSG },
    Fx { file: "N62-rb-double-quote-unterminated.runar.rb", line: 9, open: "\"cafe\n", closed: "\"cafe\"\n", msg: MSG },
    Fx { file: "N63-go-string-unterminated.runar.go", line: 18, open: "\"cafe\n", closed: "\"cafe\"\n", msg: MSG },
    Fx { file: "N64-ts-string-unterminated.runar.ts", line: 14, open: "", closed: "", msg: "" },
];

fn read(name: &str) -> String {
    let p = format!("{}/../../conformance/negatives/{}", env!("CARGO_MANIFEST_DIR"), name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {}", p, e))
}

fn expect_at(src: &str, file: &str, msg: &str, line: usize) {
    let r = parse_source(src, Some(file));
    let found = r.errors.iter().find(|d| d.message == msg);
    let all: Vec<String> = r.errors.iter().map(|d| d.format_message()).collect();
    let d = found.unwrap_or_else(|| panic!("{}: want {:?}, got {:?}", file, msg, all));
    let got = d.loc.as_ref().map(|l| l.line);
    assert_eq!(got, Some(line), "{}: {:?} at the wrong line; all: {:?}", file, msg, all);
}

fn expect_none(src: &str, file: &str) {
    let r = parse_source(src, Some(file));
    let all: Vec<String> = r.errors.iter().map(|d| d.format_message()).collect();
    assert!(!r.errors.iter().any(|d| d.message == MSG), "{}: refused as unterminated but it is not: {:?}", file, all);
}

#[test]
fn f011_conformance_negatives() {
    for f in FIXTURES {
        let src = read(f.file);
        if f.msg.is_empty() {
            assert!(!parse_source(&src, Some(f.file)).errors.is_empty(), "{}: accepted", f.file);
            continue;
        }
        expect_at(&src, f.file, f.msg, f.line);
        if !f.open.is_empty() {
            let ctl = src.replacen(f.open, f.closed, 1);
            assert_ne!(ctl, src, "{}: control replacement did not apply", f.file);
            expect_none(&ctl, f.file);
        }
    }
}

fn py(body: &str) -> String {
    format!(
        "from runar import SmartContract, Bigint, ByteString, public, assert_\n\n\nclass G(SmartContract):\n    def __init__(self):\n        super().__init__()\n\n    @public\n    def unlock(self, y: Bigint):\n{}",
        body
    )
}

#[test]
fn f011_python_shapes() {
    for lit in ["b\"ca", "b'ca", "\"ca", "'ca"] {
        expect_at(&py(&format!("        t: ByteString = {}\n        assert_(y < 5)\n", lit)), "G.runar.py", MSG, 10);
        expect_at(&py(&format!("        assert_(y < 5)\n        t: ByteString = {}", lit)), "G.runar.py", MSG, 11);
    }
    expect_at(&py("        t: ByteString = b\"ca\\\n        assert_(y < 5)\n"), "G.runar.py", MSG, 10);
    expect_at(&py("        assert_(y < 5)\n        x = \"\"\"note\n"), "G.runar.py", MSG, 11);
    expect_none(&py("        '''Method docstring\n        on two lines.'''\n        \"\"\"one line\"\"\"\n        assert_(y < 5)\n"), "G.runar.py");
}

#[test]
fn f011_other_surface_shapes() {
    expect_at("pragma runar ^0.1.0;\ncontract G is SmartContract {\n  function f() public { 'ca", "G.runar.sol", MSG, 3);
    expect_at("module G {\n    public fun f(y: Int) {\n        let t: ByteString = b\"ca\\\n", "G.runar.move", MSG, 3);
    expect_at("const runar = @import(\"runar", "G.runar.zig", MSG, 1);
    expect_at("class G extends SmartContract {\n  void f() { ByteString t = ByteString.fromHex(\"ca\\\"\n  }\n}\n", "G.runar.java", MSG, 2);
    expect_none("class G extends SmartContract {\n  void f() { ByteString t = ByteString.fromHex(\"ca\\\"fe\"); }\n}\n", "G.runar.java");
    for lit in ["'c';", "'c", "'\\''"] {
        expect_at(&format!("class G extends SmartContract {{\n  void f() {{ {}\n  }}\n}}\n", lit), "G.runar.java", CHAR_MSG, 2);
    }
    expect_at("require 'runar'\nclass G < Runar::SmartContract\n  def f(y)\n    t = \"ca\\\n  end\nend\n", "G.runar.rb", MSG, 4);
    expect_none("require 'runar'\nclass G < Runar::SmartContract\n  def f(y)\n    t = \"ca\\\"fe\"\n  end\nend\n", "G.runar.rb");
    expect_at("package contract\n\nfunc (c *G) F() {\n\tt := \"ca\\\n}\n", "G.runar.go", MSG, 4);
    // A backtick raw string (struct tag) may span lines; only EOF is unterminated.
    expect_at("package contract\n\ntype G struct {\n\tK runar.Bigint `runar:\"readonly\"\n}\n", "G.runar.go", MSG, 4);
    expect_none("package contract\n\ntype G struct {\n\tK runar.Bigint `runar:\n\"readonly\"`\n}\n", "G.runar.go");

    let rs = "use runar::prelude::*;\n\n#[runar::contract]\npub struct G {\n}\n\nimpl G {\n    pub fn unlock(&self, y: Bigint) {\n";
    expect_at(&format!("{}        let t: ByteString = \"ca\\\"\n        assert!(y < 5);\n    }}\n}}\n", rs), "G.runar.rs", MSG, 9);
    expect_none(&format!("{}        let t: ByteString = \"ca\nfe\";\n        assert!(y < 5);\n    }}\n}}\n", rs), "G.runar.rs");
}
