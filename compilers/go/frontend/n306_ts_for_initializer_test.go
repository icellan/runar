package frontend

import (
	"strings"
	"testing"
)

// N-306. A non-`let`/`const` for-initializer on .runar.ts,
// `for (i = 0n; ...)`. The TS reference's parseForStatement refuses it with
// "For loop must have a variable declaration initializer". The Go .runar.ts
// parser's parseForStatement silently substituted the synthetic `_i = 0`
// iterator instead, discarding the real initializer expression entirely with
// no diagnostic. That substitution is invisible when the condition/update
// still reference the ORIGINAL name `i`: a later validator (the unrolled-loop
// "condition must compare the loop variable '_i'" check) accidentally catches
// the name mismatch and refuses the program anyway, for an unrelated reason.
// Writing the condition/update against `_i` (the substituted name) instead --
// exactly what a developer copy-pasting the substituted iterator would do --
// defeats that accidental catch and the garbage initializer compiles clean.
//
// Proves: the Go .runar.ts parser refuses a non-declaration for-initializer
// with the TS reference's diagnostic text. Does not prove: other Go-tier
// surfaces, or other tiers (pinned by the conformance negatives N277-N279).
func n306Wrap(init string) string {
	return `import { StatefulSmartContract, assert } from 'runar-lang';

class InitProbe extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) { super(count); this.count = count; }

  public unlock(expected: bigint): void {
    let acc: bigint = 0n;
    for (` + init + `; _i < 3n; _i++) {
      acc = acc + 1n;
    }
    assert(acc === expected);
  }
}
`
}

func TestN306_NonDeclarationForInitializerIsRefused(t *testing.T) {
	res := ParseSource([]byte(n306Wrap("i = 0n")), "InitProbe.runar.ts")
	found := false
	for _, e := range res.Errors {
		if strings.Contains(e.Message, "For loop must have a variable declaration initializer") {
			found = true
		}
	}
	if !found {
		t.Errorf("non-declaration for-initializer was not refused with the TS diagnostic; errors: %v", res.Errors)
	}
}

// A well-formed `let` initializer must keep compiling clean: the fix narrows
// the else-branch of the initializer dispatch, it must not touch the
// `let`/`const` branch.
func TestN306_LetInitializerStillParsesClean(t *testing.T) {
	res := ParseSource([]byte(n306Wrap("let i: bigint = 0n")), "InitProbe.runar.ts")
	if res.Contract == nil {
		t.Fatalf("a `let` for-initializer must still parse clean; errors: %v", res.Errors)
	}
}
