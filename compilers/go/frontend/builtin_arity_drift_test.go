package frontend

import (
	"testing"

	"github.com/icellan/runar/compilers/go/ir"
)

// R-163 / R-165 — `ir.BuiltinArity` is the arity half of this package's
// `builtinFunctions`, duplicated into `ir` because the dependency runs
// frontend -> ir and cannot run back. A second copy of anything is a drift
// risk, so the copy is checked here rather than trusted.
//
// Two builtins legitimately differ: `assert` accepts 1 or 2 arguments and
// `extractPrevOutputScript` accepts 2 or 3, both special-cased in
// `checkCallArgs` for the same reason (an optional trailing argument the
// signature table cannot express).
func TestBuiltinArityMatchesFrontendTable(t *testing.T) {
	variable := map[string][]int{
		"assert":                  {1, 2},
		"extractPrevOutputScript": {2, 3},
	}

	// Names whose arity is a RULE rather than a count live in
	// `ir.VariadicArityOK` instead of the table.
	variadic := map[string]bool{"merkleRootPoseidon2KB": true}

	for name, sig := range builtinFunctions {
		if variadic[name] {
			if _, _, isVariadic := ir.VariadicArityOK(name, 10); !isVariadic {
				t.Errorf("%q is variadic in the frontend but ir has no rule for it", name)
			}
			continue
		}
		allowed, ok := ir.AllowedArity(name)
		if !ok {
			t.Errorf("ir.BuiltinArity is missing %q — a builtin the frontend knows, "+
				"so wrong-arity IR calling it passes validation unchecked", name)
			continue
		}
		want := []int{len(sig.params)}
		if v, special := variable[name]; special {
			want = v
		}
		if len(allowed) != len(want) {
			t.Errorf("%q: ir table allows %v, frontend says %v", name, allowed, want)
			continue
		}
		for i := range want {
			if allowed[i] != want[i] {
				t.Errorf("%q: ir table allows %v, frontend says %v", name, allowed, want)
				break
			}
		}
	}

	for name := range ir.BuiltinArity {
		if _, ok := builtinFunctions[name]; !ok {
			t.Errorf("ir.BuiltinArity carries %q, which the frontend does not know — "+
				"a stale entry rejects valid IR", name)
		}
	}
}
