//! N-021 (CL-BUG-197) — `=begin` ... `=end` embedded documents in .runar.rb.
//!
//! Pre-fix this tier's Ruby-surface tokenizer knew only `#` comments. In a
//! column-0 `=begin` ... `=end` block every line was lexed as code: the
//! "commented-out" `drain` became a live spend path, the `=` of `=end` was
//! skipped as an unknown class-body token and its `end` closed the class
//! early, dropping the guarded `unlock`. The crafted contract below compiled
//! to 517777 (OP_TRUE OP_NIP OP_NIP, anyone-can-spend) with ABI [drain].
//!
//! The rule (user decision R11) is the Ruby tier's F-018 rule, ported to Go by
//! F-012, which is Ruby's own: `=begin` / `=end` open and close a block
//! comment only at column 0 and only as a whole word (followed by whitespace
//! or end of line); every line from `=begin` through `=end` is a comment; an
//! unterminated `=begin` is refused with
//! "unterminated '=begin' block comment starting at line N: missing '=end'"
//! at line N, column 0 (no column), exactly as the Go tier locates it.
//!
//! What this proves: this tier parses the crafted contract to exactly
//! `unlock` (LF, CRLF, text or a tab after the markers) and compiles it
//! (fold OFF) to the basic-p2pkh golden with ABI [unlock]; an unterminated
//! `=begin` (also one "closed" only by `=endx`) is refused with the shared
//! text at its line; an indented `=begin` and `=beginx` are not openers.
//! What it does NOT prove: other tiers; the parser's separate silent skip of
//! unknown class-body tokens (N-004); `__END__` or other Ruby lexical forms.

use runar_compiler_rust::frontend::parser::parse_source;
use runar_compiler_rust::{compile_from_source_str_with_options, CompileOptions};

const FILE: &str = "P2PKH.runar.rb";
const BEGIN_LINE: usize = 11;

fn attack() -> String {
    [
        "require 'runar'",
        "",
        "class P2PKH < Runar::SmartContract",
        "  prop :pub_key_hash, Addr",
        "",
        "  def initialize(pub_key_hash)",
        "    super(pub_key_hash)",
        "    @pub_key_hash = pub_key_hash",
        "  end",
        "",
        "=begin",
        "  Old debugging entry point, disabled:",
        "  runar_public sig: Sig, pk: PubKey",
        "  def drain(sig, pk)",
        "    assert true",
        "  end",
        "end",
        "=end",
        "",
        "  runar_public sig: Sig, pub_key: PubKey",
        "  def unlock(sig, pub_key)",
        "    assert hash160(pub_key) == @pub_key_hash",
        "    assert check_sig(sig, pub_key)",
        "  end",
        "end",
        "",
    ]
    .join("\n")
}

fn unterminated_msg(line: usize) -> String {
    format!("unterminated '=begin' block comment starting at line {}: missing '=end'", line)
}

fn golden() -> String {
    let p = format!(
        "{}/../../conformance/tests/basic-p2pkh/expected-script.hex",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {}", p, e)).trim().to_string()
}

fn methods(src: &str) -> Vec<String> {
    parse_source(src, Some(FILE))
        .contract
        .map(|c| c.methods.iter().map(|m| m.name.clone()).collect())
        .unwrap_or_default()
}

fn variants() -> Vec<(&'static str, String)> {
    let a = attack();
    vec![
        ("lf", a.clone()),
        ("crlf", a.replace('\n', "\r\n")),
        (
            "text after markers",
            a.replacen("\n=begin\n", "\n=begin legacy notes\n", 1)
                .replacen("\n=end\n", "\n=end trailing words\n", 1),
        ),
        (
            "tab after markers",
            a.replacen("\n=begin\n", "\n=begin\tx\n", 1).replacen("\n=end\n", "\n=end\tx\n", 1),
        ),
    ]
}

#[test]
fn n021_backdoor_is_not_a_spend_path() {
    for (name, src) in variants() {
        let r = parse_source(&src, Some(FILE));
        let errs: Vec<String> = r.errors.iter().map(|e| e.message.clone()).collect();
        assert!(errs.is_empty(), "{}: unexpected errors {:?}", name, errs);
        let c = r.contract.expect("contract");
        let ms: Vec<&str> = c.methods.iter().map(|m| m.name.as_str()).collect();
        assert_eq!(ms, vec!["unlock"], "{}: methods", name);
        let ps: Vec<&str> = c.properties.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(ps, vec!["pubKeyHash"], "{}: properties", name);
    }
}

#[test]
fn n021_compiles_to_the_basic_p2pkh_golden() {
    let want = golden();
    for (name, src) in variants() {
        let opts = CompileOptions { disable_constant_folding: true, ..Default::default() };
        let art = compile_from_source_str_with_options(&src, Some(FILE), &opts)
            .unwrap_or_else(|e| panic!("{}: compile failed: {}", name, e));
        let public: Vec<&str> =
            art.abi.methods.iter().filter(|m| m.is_public).map(|m| m.name.as_str()).collect();
        assert_eq!(public, vec!["unlock"], "{}: public ABI", name);
        assert_eq!(art.script.to_lowercase(), want, "{}: script (asm {})", name, art.asm);
    }
}

#[test]
fn n021_unterminated_begin_is_refused_at_its_line() {
    let src = attack().replacen("\n=end\n", "\n", 1);
    let r = parse_source(&src, Some(FILE));
    let want = unterminated_msg(BEGIN_LINE);
    let d = r
        .errors
        .iter()
        .find(|e| e.message == want)
        .unwrap_or_else(|| panic!("errors = {:?}, want {:?}", r.errors, want));
    let loc = d.loc.as_ref().expect("located diagnostic");
    // N-078 (R88a): the location is stored in the AST's 1-based column
    // convention (first column = 1) and printed 0-based, so column 0 prints.
    assert_eq!((loc.line, loc.column), (BEGIN_LINE, 1));
    assert_eq!(d.format_message(), format!("{}:{}:0: {}", FILE, BEGIN_LINE, want));
}

#[test]
fn n021_endx_does_not_close_a_block() {
    let src = attack().replacen("\n=end\n", "\n=endx\n", 1);
    let r = parse_source(&src, Some(FILE));
    assert!(
        r.errors.iter().any(|e| e.message == unterminated_msg(BEGIN_LINE)),
        "errors = {:?}",
        r.errors
    );
}

#[test]
fn n021_begin_on_last_line_is_unterminated() {
    let r = parse_source("require 'runar'\n=begin", Some(FILE));
    assert!(r.errors.iter().any(|e| e.message == unterminated_msg(2)), "errors = {:?}", r.errors);
}

// Boundary controls: only a column-0 whole-word `=begin` opens a comment, so
// the lines after these are still lexed as code (`drain` is parsed).
#[test]
fn n021_indented_begin_is_not_a_comment() {
    let src = attack().replacen("\n=begin\n", "\n  =begin\n", 1).replacen("\n=end\n", "\n  =end\n", 1);
    assert!(methods(&src).contains(&"drain".to_string()));
}

#[test]
fn n021_beginx_is_not_a_comment() {
    let src = attack().replacen("\n=begin\n", "\n=beginx\n", 1);
    assert!(methods(&src).contains(&"drain".to_string()));
}
