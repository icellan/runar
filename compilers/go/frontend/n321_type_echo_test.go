package frontend

// N-321: typecheck diagnostics must not echo an unbounded type text.
//
// What this proves: a ~1 MB flat identifier type annotation that typecheck
// refuses produces diagnostics bounded in size, carrying an elision marker,
// while an ordinary-size type is echoed verbatim.
// What it does NOT prove: the other tiers (conformance/negatives parity test)
// or every echo site individually (it drives the declaration-init mismatch).

import (
	"strings"
	"testing"
)

const n321Head = "import { SmartContract, assert } from 'runar-lang';\nclass P extends SmartContract {\n readonly t: bigint;\n constructor(t: bigint) { super(t); this.t = t; }\n public verify(a: bigint) {\n let q: {T} = a;\n assert(q == this.t);\n }\n}\n"

func n321Errors(typ string) []string {
	src := strings.Replace(n321Head, "{T}", typ, 1)
	res := ParseSource([]byte(src), "P.runar.ts")
	var out []string
	out = append(out, res.ErrorStrings()...)
	if res.Contract != nil {
		for _, d := range TypeCheck(res.Contract).Errors {
			out = append(out, d.Message)
		}
	}
	return out
}

func TestN321_HugeTypeTextIsElidedInDiagnostics(t *testing.T) {
	huge := strings.Repeat("T", 1<<20)
	errs := n321Errors(huge)
	if len(errs) == 0 {
		t.Fatal("expected a refusal for an unknown 1 MB type name")
	}
	total := 0
	for _, e := range errs {
		total += len(e)
	}
	if total > 4096 {
		t.Errorf("diagnostics total %d bytes, want <= 4096", total)
	}
	if !strings.Contains(strings.Join(errs, "\n"), "...(") {
		t.Errorf("no elision marker in %d diagnostics", len(errs))
	}
}

func TestN321_OrdinaryTypeTextUnchanged(t *testing.T) {
	errs := n321Errors("ByteString")
	if got := strings.Join(errs, "\n"); !strings.Contains(got, "type 'ByteString' is not assignable to type 'bigint'") && !strings.Contains(got, "'ByteString'") {
		t.Errorf("ordinary diagnostic changed: %q", errs)
	}
}
