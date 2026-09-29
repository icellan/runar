package frontend

import (
	"reflect"
	"testing"
)

// F-039 — a `@sighash` marker that is present but not followed by a
// well-formed flag list (e.g. `@sighash SINGLE|FORKID!`) used to be read as
// "no directive": the method compiled, silently, under the default ALL|FORKID.
// A second directive on the same method was silently ignored (and Go, which
// concatenates stacked comments nearest-first, let the LAST block win where
// the reference let the first win).
//
// Proves: the Go TS-surface parser refuses each malformed / duplicated shape
// with the diagnostic shared by all seven tiers, keeps the reference
// word-boundary rule (`@sighashSINGLE` / `@sighashType` are prose, not
// markers), and still honours a well-formed multi-line JSDoc directive.
// Does not prove: cross-tier agreement (conformance/negatives rejection-parity).

const (
	f039Malformed = "Method 'bump': @sighash: malformed directive; expected `@sighash <FLAGS>` where FLAGS is a |-separated list of ALL, NONE, SINGLE, FORKID, ANYONECANPAY (e.g. `@sighash SINGLE|FORKID`)"
	f039Multiple  = "Method 'bump': @sighash: more than one @sighash directive on this method; declare exactly one"
)

func f039Src(directive string) string {
	return `
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        ` + directive + `
        public bump(): void { this.addOutput(1000n, this.n); }
      }`
}

func f039Errors(directive string) []string {
	res := ParseSource([]byte(f039Src(directive)), "X.runar.ts")
	var out []string
	for _, e := range res.Errors {
		out = append(out, e.Message)
	}
	return out
}

func TestF039_MalformedDirectiveRejected(t *testing.T) {
	for _, d := range []string{
		"/** @sighash SINGLE|FORKID! */",
		"/** @sighash:SINGLE|FORKID */",
		"// @sighash=SINGLE|FORKID",
		"/** @sighash SINGLE,FORKID */",
	} {
		if got := f039Errors(d); !reflect.DeepEqual(got, []string{f039Malformed}) {
			t.Errorf("%q: errors = %q, want [%q]", d, got, f039Malformed)
		}
	}
}

func TestF039_BareMarkerLineCommentRejected(t *testing.T) {
	want := []string{"Method 'bump': @sighash directive requires at least one flag (e.g. `@sighash ALL|FORKID`)"}
	if got := f039Errors("// @sighash"); !reflect.DeepEqual(got, want) {
		t.Errorf("errors = %q, want %q", got, want)
	}
}

func TestF039_MultipleDirectivesRejected(t *testing.T) {
	for _, d := range []string{
		"/** @sighash SINGLE|FORKID\n   * @sighash ALL|FORKID */",
		"/** @sighash SINGLE|FORKID */\n        /** @sighash ALL|FORKID */",
		"/** @sighash SINGLE|FORKID!\n   * @sighash NONE|FORKID */",
	} {
		if got := f039Errors(d); !reflect.DeepEqual(got, []string{f039Multiple}) {
			t.Errorf("%q: errors = %q, want [%q]", d, got, f039Multiple)
		}
	}
}

func TestF039_WordBoundaryProseIsNotAMarker(t *testing.T) {
	for _, d := range []string{"/** @sighashSINGLE|FORKID */", "/** see the @sighashType docs */"} {
		if m := sighashMethodByName(t, f039Src(d), "bump"); m.SighashType != nil {
			t.Errorf("%q: SighashType = %v, want nil", d, *m.SighashType)
		}
	}
}

func TestF039_WellFormedMultilineJSDocHonoured(t *testing.T) {
	m := sighashMethodByName(t, f039Src("/**\n   * Bump.\n   * @sighash SINGLE|FORKID\n   */"), "bump")
	if m.SighashType == nil || *m.SighashType != 0x43 {
		t.Fatalf("SighashType = %v, want 0x43", m.SighashType)
	}
}
