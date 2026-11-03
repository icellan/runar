package frontend

import (
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// F-012 (CL-BUG-197): the .runar.rb tokenizer did not know Ruby's
// `=begin` ... `=end` embedded documents.
//
// Pre-fix, the block was lexed as live code. A method "commented out" inside
// it became a real spending entry point. The `=` of `=end` was then skipped as
// an unknown class-body token, and its `end` closed the class early, so the
// real guarded method after the block was dropped, with no diagnostic. The
// crafted contract below (P2PKH `unlock` plus a commented-out `drain` backdoor)
// compiled to the 3-byte `OP_TRUE OP_NIP OP_NIP`. That is anyone-can-spend,
// and @bsv/sdk Spend.validate accepted it with an empty-sig, junk-pubkey
// unlocking script (evidence in the F-012 remediation log).
//
// The rule is the Ruby tier's (F-018, compilers/ruby parser_ruby.rb), which
// is Ruby's own: `=begin` and `=end` open and close a block comment only at
// column 0 and only as a whole word (followed by whitespace or end of line).
// Every line from `=begin` through `=end` is a comment, including any text
// after the marker on the same line. An unterminated `=begin` is refused with
// "unterminated '=begin' block comment starting at line N: missing '=end'".
//
// What this proves: the crafted contract parses to exactly `unlock` with the
// `pubKeyHash` property and no errors (also with CRLF line endings and with
// text after either marker); the block's tokens never reach the token stream;
// an unterminated `=begin` is refused with that text at the opener's line;
// an indented `=begin` and `=beginx` are not comment openers.
// What this does not prove: the emitted bytes (compiler/f012 test pins those
// to the basic-p2pkh golden); the parser's separate silent skip of unknown
// class-body tokens, which the TS reference shares and which is left alone;
// any other tier (TS, Rust, Python, Zig and Java still lex the block as code).
// ---------------------------------------------------------------------------

// f012AttackSource is built by concatenation, not a raw string with
// indentation, because `=begin` / `=end` must sit at column 0 exactly as an
// attacker would place them.
var f012AttackSource = strings.Join([]string{
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
}, "\n")

// f012BeginLine is the 1-based line of `=begin` in f012AttackSource.
const f012BeginLine = 11

func f012MethodNames(r *ParseResult) []string {
	var names []string
	for _, m := range r.Contract.Methods {
		names = append(names, m.Name)
	}
	return names
}

func f012Idents(source string) []string {
	p := &rbParser{fileName: "P2PKH.runar.rb"}
	var idents []string
	for _, tok := range p.tokenize(source) {
		if tok.kind == rbTokIdent {
			idents = append(idents, tok.value)
		}
	}
	return idents
}

func f012Contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

func TestF012_RubyBlockComment_BackdoorIsNotASpendPath(t *testing.T) {
	cases := map[string]string{
		"lf":   f012AttackSource,
		"crlf": strings.ReplaceAll(f012AttackSource, "\n", "\r\n"),
		"text after markers": strings.Replace(
			strings.Replace(f012AttackSource, "\n=begin\n", "\n=begin legacy notes\n", 1),
			"\n=end\n", "\n=end trailing words\n", 1),
		"tab after markers": strings.Replace(
			strings.Replace(f012AttackSource, "\n=begin\n", "\n=begin\tx\n", 1),
			"\n=end\n", "\n=end\tx\n", 1),
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			r := ParseRuby([]byte(src), "P2PKH.runar.rb")
			if len(r.Errors) != 0 {
				t.Fatalf("unexpected parse errors: %v", r.Errors)
			}
			if r.Contract == nil {
				t.Fatal("no contract")
			}
			got := f012MethodNames(r)
			if len(got) != 1 || got[0] != "unlock" {
				t.Fatalf("methods = %v, want [unlock]: the =begin/=end block must be a comment (no `drain`), and `unlock` after it must survive", got)
			}
			if len(r.Contract.Properties) != 1 || r.Contract.Properties[0].Name != "pubKeyHash" {
				t.Fatalf("properties = %+v, want [pubKeyHash]", r.Contract.Properties)
			}
		})
	}
}

func TestF012_RubyBlockComment_RemovedFromTokenStream(t *testing.T) {
	idents := f012Idents(f012AttackSource)
	if f012Contains(idents, "drain") || f012Contains(idents, "begin") {
		t.Fatalf("block comment leaked into the token stream: idents = %v", idents)
	}
}

func TestF012_RubyBlockComment_UnterminatedIsRefused(t *testing.T) {
	src := strings.Replace(f012AttackSource, "\n=end\n", "\n", 1)
	r := ParseRuby([]byte(src), "P2PKH.runar.rb")
	want := "unterminated '=begin' block comment starting at line 11: missing '=end'"
	for _, d := range r.Errors {
		if d.Message == want {
			if d.Loc == nil || d.Loc.Line != f012BeginLine || d.Loc.Column != 0 {
				t.Fatalf("diagnostic at %+v, want line %d column 0", d.Loc, f012BeginLine)
			}
			return
		}
	}
	t.Fatalf("errors = %v, want %q", r.Errors, want)
}

// The two tests below pin the rule's boundary at the tokenizer: only a
// column-0, whole-word `=begin` opens a comment, so the lines after it are
// still lexed. They deliberately assert nothing about the parse result; the
// parser's tolerance of stray class-body tokens is a separate matter.
func TestF012_RubyBlockComment_IndentedBeginIsNotAComment(t *testing.T) {
	src := strings.Replace(strings.Replace(f012AttackSource, "\n=begin\n", "\n  =begin\n", 1), "\n=end\n", "\n  =end\n", 1)
	if !f012Contains(f012Idents(src), "drain") {
		t.Fatal("an indented =begin must not open a block comment (Ruby only recognises column 0)")
	}
}

func TestF012_RubyBlockComment_BeginPrefixWordIsNotAComment(t *testing.T) {
	src := strings.Replace(f012AttackSource, "\n=begin\n", "\n=beginx\n", 1)
	if !f012Contains(f012Idents(src), "drain") {
		t.Fatal("`=beginx` is not a block-comment opener")
	}
}
