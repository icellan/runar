//! N-004 (CL-BUG-257) — stray class-level tokens in .runar.rb.
//!
//! The parser skipped any class-body token it did not recognise and ignored
//! everything after the class's `end`. An INDENTED `=begin` is not a comment
//! in Ruby: it lexes as `=` then `begin`, both were skipped, the
//! "commented-out" `drain` became a method, the block's `end` closed the
//! class, and the real guarded `unlock` was dropped with no diagnostic,
//! leaving `drain` (assert true) as the only spend path.
//!
//! The rule is the TS reference's: a class-body token other than `prop`,
//! `runar_public`, `params`, `def` or a bare `private` / `public` marker is
//! refused with "Unexpected token in class body: '<tok>'", and the first token
//! after the class's `end` with "Unexpected token after class end: '<tok>'".
//!
//! What this proves: the indented backdoor, stray class-body tokens and
//! trailing code after the class are parse errors whose first diagnostic is
//! the shared text; bare `private` / `public` markers and trailing blank lines
//! and comments still parse cleanly.
//! What it does NOT prove: emitted bytes, other tiers (see
//! conformance/negatives/n004-rb-stray-token-parity.test.ts), characters the
//! tokenizer drops, or a class with no closing `end`.

use runar_compiler_rust::frontend::parser::parse_source;

const FILE: &str = "P2PKH.runar.rb";

fn p2pkh(body: &str, tail: &str) -> String {
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
        body,
        "  runar_public sig: Sig, pub_key: PubKey",
        "  def unlock(sig, pub_key)",
        "    assert hash160(pub_key) == @pub_key_hash",
        "    assert check_sig(sig, pub_key)",
        "  end",
        "end",
        tail,
    ]
    .join("\n")
}

fn indented() -> String {
    p2pkh(
        &[
            "",
            "  =begin",
            "  Old debugging entry point, disabled:",
            "  runar_public sig: Sig, pk: PubKey",
            "  def drain(sig, pk)",
            "    assert true",
            "  end",
            "end",
            "  =end",
            "",
        ]
        .join("\n"),
        "",
    )
}

fn body(tok: &str) -> String {
    format!("Unexpected token in class body: '{}'", tok)
}

fn after(tok: &str) -> String {
    format!("Unexpected token after class end: '{}'", tok)
}

#[test]
fn n004_stray_class_level_tokens_are_refused() {
    let cases: Vec<(&str, String, String)> = vec![
        ("indented =begin backdoor", indented(), body("=")),
        ("stray 42 + ?", p2pkh("\n  42 + ?\n", ""), body("42")),
        ("stray = end", p2pkh("\n  = end\n", ""), body("=")),
        ("bare identifier", p2pkh("\n  foo\n", ""), body("foo")),
        ("identifier after class", p2pkh("", "foo\n"), after("foo")),
        ("end after class", p2pkh("", "end\n"), after("end")),
        ("method after class", p2pkh("", "def drain(sig)\n  assert true\nend\n"), after("def")),
        ("class after class", p2pkh("", "class Other < Runar::SmartContract\nend\n"), after("class")),
    ];
    for (name, src, want) in cases {
        let r = parse_source(&src, Some(FILE));
        let first = r.errors.first().map(|e| e.message.clone());
        assert_eq!(first.as_deref(), Some(want.as_str()), "{}: errors {:?}", name, r.errors);
    }
}

#[test]
fn n004_visibility_markers_and_trailing_blanks_are_accepted() {
    for (name, src) in [
        ("plain", p2pkh("", "")),
        ("private / public", p2pkh("\n  private\n\n  public\n", "")),
        ("trailing comment", p2pkh("", "\n# trailing note\n\n")),
    ] {
        let r = parse_source(&src, Some(FILE));
        assert!(r.errors.is_empty() && r.contract.is_some(), "{}: {:?}", name, r.errors);
    }
}
