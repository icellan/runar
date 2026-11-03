package compiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F-012 (CL-BUG-197): a `=begin` ... `=end` block in a .runar.rb contract is
// a comment and contributes nothing to the script.
//
// Pre-fix this crafted P2PKH contract, with a commented-out `drain` backdoor,
// compiled to 517777 (OP_TRUE OP_NIP OP_NIP, anyone-can-spend) with `drain`
// as its only public method. See frontend/f012_ruby_block_comment_test.go.
//
// What this proves: the contract compiles (fold OFF) to an ABI whose only
// public method is `unlock`, and to a locking script byte-identical to the
// checked-in basic-p2pkh golden. That is the same hex the Ruby tier emits for
// this source after F-018.
// What this does not prove: spend behaviour of that golden, which its own
// provenance gate covers, or anything about the other tiers.
func TestF012_RubyBlockComment_CompilesToP2PKHGolden(t *testing.T) {
	golden, err := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "tests", "basic-p2pkh", "expected-script.hex"))
	if err != nil {
		t.Fatalf("read golden: %v", err)
	}
	source := strings.Join([]string{
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

	res := CompileFromSourceStrWithResult(source, "P2PKH.runar.rb", CompileOptions{DisableConstantFolding: true})
	if !res.Success || res.Artifact == nil {
		t.Fatalf("compilation failed: %v", res.Diagnostics)
	}
	var public []string
	for _, m := range res.Artifact.ABI.Methods {
		if m.IsPublic {
			public = append(public, m.Name)
		}
	}
	if len(public) != 1 || public[0] != "unlock" {
		t.Fatalf("public ABI methods = %v, want [unlock]", public)
	}
	want := strings.TrimSpace(string(golden))
	if got := strings.ToLower(res.Artifact.Script); got != want {
		t.Fatalf("script = %s (asm %s), want the basic-p2pkh golden %s", got, res.Artifact.ASM, want)
	}
}
