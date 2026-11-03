package frontend

import (
	"fmt"
	"testing"
)

// N-303 — a decorated `def __init__` in .runar.py is the constructor.
//
// The TS reference (parseMethodDef in 01-parse-python.ts) decides "this is
// the constructor" from the method NAME alone, whatever decorators precede it:
// `@public def __init__` and `@foo def __init__` both yield the ordinary
// constructor and add no method. Before the fix this tier sent every
// decorated `def` down the method path, so the constructor became a method
// named "constructor" next to an auto-generated constructor.
//
// What this proves: the Go tier's .runar.py frontend produces the same AST
// shape as the undecorated control for a decorated __init__ (one constructor
// with the declared params, only `unlock` in the method list, no errors).
// What it does NOT prove: the other tiers (their own suites / the matrix in
// the N-303 log), or the compiled hex.

func n303Py(decorator string) string {
	return "from runar import SmartContract, Addr, Sig, PubKey, public, assert_, hash160, check_sig\n\n" +
		"class P2PKH(SmartContract):\n" +
		"    pub_key_hash: Addr\n\n" +
		decorator +
		"    def __init__(self, pub_key_hash: Addr):\n" +
		"        super().__init__(pub_key_hash)\n" +
		"        self.pub_key_hash = pub_key_hash\n\n" +
		"    @public\n" +
		"    def unlock(self, sig: Sig, pub_key: PubKey):\n" +
		"        assert_(hash160(pub_key) == self.pub_key_hash)\n" +
		"        assert_(check_sig(sig, pub_key))\n"
}

func TestN303_DecoratedInitIsTheConstructor(t *testing.T) {
	cases := []struct{ label, decorator string }{
		{"undecorated", ""},
		{"@public", "    @public\n"},
		{"@foo", "    @foo\n"},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			res := ParseSource([]byte(n303Py(c.decorator)), "P2PKH.runar.py")
			if len(res.Errors) != 0 {
				t.Fatalf("unexpected errors: %v", res.Errors)
			}
			if res.Contract == nil {
				t.Fatal("no contract")
			}
			var names []string
			for _, m := range res.Contract.Methods {
				names = append(names, m.Name)
			}
			if fmt.Sprint(names) != "[unlock]" {
				t.Errorf("methods = %v, want [unlock]", names)
			}
			var params []string
			for _, p := range res.Contract.Constructor.Params {
				params = append(params, p.Name)
			}
			if res.Contract.Constructor.Name != "constructor" || fmt.Sprint(params) != "[pubKeyHash]" {
				t.Errorf("constructor = %s%v, want constructor[pubKeyHash]", res.Contract.Constructor.Name, params)
			}
		})
	}
}
