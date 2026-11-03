package frontend

import (
	"strings"
	"testing"
)

// N-004 (CL-BUG-257): the .runar.rb parser skipped any class-body token it did
// not recognise and ignored everything after the class's `end`. An INDENTED
// `=begin` is not a comment in Ruby: it lexes as `=` then `begin`, both were
// skipped, the "commented-out" `drain` became a method, the block's `end`
// closed the class, and the real guarded `unlock` was dropped with no
// diagnostic, leaving `drain` (assert true) as the only spend path.
//
// The rule is the TS reference's: a class-body token other than `prop`,
// `runar_public`, `params`, `def` or a bare `private` / `public` marker is
// refused with "Unexpected token in class body: '<tok>'", and the first token
// after the class's `end` with "Unexpected token after class end: '<tok>'".
//
// What this proves: the indented backdoor, stray class-body tokens and
// trailing code after the class are parse errors whose first diagnostic is
// the shared text; bare `private` / `public` markers and trailing blank lines
// and comments still parse cleanly.
// What this does not prove: the emitted bytes, any other tier (see
// conformance/negatives/n004-rb-stray-token-parity.test.ts), characters the
// tokenizer drops before they reach the parser, or a class with no `end`.

func n004P2PKH(body, tail string) string {
	return strings.Join([]string{
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
	}, "\n")
}

var n004Indented = n004P2PKH(strings.Join([]string{
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
}, "\n"), "")

func TestN004_RubyStrayTokensRefused(t *testing.T) {
	body := func(tok string) string { return "Unexpected token in class body: '" + tok + "'" }
	after := func(tok string) string { return "Unexpected token after class end: '" + tok + "'" }
	cases := []struct{ name, src, want string }{
		{"indented =begin backdoor", n004Indented, body("=")},
		{"stray 42 + ?", n004P2PKH("\n  42 + ?\n", ""), body("42")},
		{"stray = end", n004P2PKH("\n  = end\n", ""), body("=")},
		{"bare identifier", n004P2PKH("\n  foo\n", ""), body("foo")},
		{"identifier after class", n004P2PKH("", "foo\n"), after("foo")},
		{"end after class", n004P2PKH("", "end\n"), after("end")},
		{"method after class", n004P2PKH("", "def drain(sig)\n  assert true\nend\n"), after("def")},
		{"class after class", n004P2PKH("", "class Other < Runar::SmartContract\nend\n"), after("class")},
	}
	for _, c := range cases {
		res := ParseRuby([]byte(c.src), "P2PKH.runar.rb")
		if len(res.Errors) == 0 {
			t.Errorf("%s: parsed with no errors", c.name)
			continue
		}
		if res.Errors[0].Message != c.want {
			t.Errorf("%s: first error %q, want %q", c.name, res.Errors[0].Message, c.want)
		}
	}
}

func TestN004_RubyVisibilityMarkersAndTrailingBlanksAccepted(t *testing.T) {
	for name, src := range map[string]string{
		"plain":            n004P2PKH("", ""),
		"private / public": n004P2PKH("\n  private\n\n  public\n", ""),
		"trailing comment": n004P2PKH("", "\n# trailing note\n\n"),
	} {
		res := ParseRuby([]byte(src), "P2PKH.runar.rb")
		if len(res.Errors) != 0 || res.Contract == nil {
			t.Errorf("%s: %v", name, res.Errors)
		}
	}
}
