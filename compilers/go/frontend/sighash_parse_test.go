package frontend

import (
	"fmt"
	"strings"
	"testing"
)

// #123 @sighash directive parsing (TS surface) — port of sighash-parse.test.ts.

func sighashMethodByName(t *testing.T, src, name string) *MethodNode {
	t.Helper()
	res := ParseSource([]byte(src), "X.runar.ts")
	if len(res.Errors) > 0 {
		t.Fatalf("unexpected parse errors: %v", res.ErrorStrings())
	}
	if res.Contract == nil {
		t.Fatal("no contract parsed")
	}
	for i := range res.Contract.Methods {
		if res.Contract.Methods[i].Name == name {
			return &res.Contract.Methods[i]
		}
	}
	t.Fatalf("method %q not found", name)
	return nil
}

func TestSighashParse_SetsTypeFromJSDoc(t *testing.T) {
	src := `
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @sighash SINGLE|FORKID */
        public bump(): void { this.n = this.n + 1n; }
      }`
	m := sighashMethodByName(t, src, "bump")
	if m.SighashType == nil || *m.SighashType != 0x43 {
		t.Fatalf("SighashType = %v, want 0x43", m.SighashType)
	}
}

func TestSighashParse_NilWhenNoDirective(t *testing.T) {
	src := `
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        public bump(): void { this.n = this.n + 1n; }
      }`
	m := sighashMethodByName(t, src, "bump")
	if m.SighashType != nil {
		t.Fatalf("SighashType = %v, want nil (default)", *m.SighashType)
	}
}

func TestSighashParse_LineComment(t *testing.T) {
	src := `
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        // @sighash NONE|FORKID
        public wipe(): void { this.n = 0n; }
      }`
	m := sighashMethodByName(t, src, "wipe")
	if m.SighashType == nil || *m.SighashType != 0x42 {
		t.Fatalf("SighashType = %v, want 0x42", m.SighashType)
	}
}

func TestSighashParse_ErrorOnBadCombo(t *testing.T) {
	src := `
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @sighash ALL|NONE|FORKID */
        public bump(): void { this.n = this.n + 1n; }
      }`
	res := ParseSource([]byte(src), "X.runar.ts")
	if !anyErrContains(res, "cannot combine base types") {
		t.Fatalf("want cannot-combine error, got %v", res.ErrorStrings())
	}
}

func TestSighashParse_ErrorOnPrivateMethod(t *testing.T) {
	src := `
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @sighash SINGLE|FORKID */
        private helper(): bigint { return 1n; }
        public bump(): void { this.n = this.n + 1n; }
      }`
	res := ParseSource([]byte(src), "X.runar.ts")
	if !anyErrContains(res, "non-public method") {
		t.Fatalf("want non-public-method error, got %v", res.ErrorStrings())
	}
}

func TestSighashParse_RejectsMissingForkID(t *testing.T) {
	src := `
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; }
        /** @sighash SINGLE */
        public bump(): void { this.n = this.n + 1n; }
      }`
	res := ParseSource([]byte(src), "X.runar.ts")
	if !anyErrContains(res, "FORKID is mandatory on BSV") {
		t.Fatalf("want FORKID-mandatory error, got %v", res.ErrorStrings())
	}
}

// F-282: `leadingCommentText` walked `PrevSibling()` with no line check, so a
// directive comment sharing a line with the PRECEDING member's own last
// token was collected as a prevSibling regardless — ts-morph never attaches
// it (verified directly against ts-morph: it is the preceding token's
// trailing trivia, not this node's leading trivia).
func TestSighashParse_SharedLineWithPrecedingMemberNotHonoured(t *testing.T) {
	src := `
      class C extends StatefulSmartContract {
        n: bigint;
        constructor(n: bigint) { super(n); this.n = n; } /** @sighash SINGLE|FORKID */ public bump(): void { this.n = this.n + 1n; }
      }`
	// N-199 (R75): ts-morph still does not attach it, and the lost directive
	// is now refused instead of compiling under the default ALL|FORKID.
	res := ParseSource([]byte(src), "X.runar.ts")
	if len(res.Errors) != 1 || res.Errors[0].Message != LostDirectiveMsg("@sighash") {
		t.Fatalf("errors = %v, want exactly the N-199 lost-directive refusal", res.ErrorStrings())
	}
	for _, m := range res.Contract.Methods {
		if m.Name == "bump" && m.SighashType != nil {
			t.Fatalf("SighashType = %v, want nil — ts-morph drops a same-line-as-preceding-token directive", *m.SighashType)
		}
	}
}

// N-199 (user decision R75): a `@sighash` / `@embedAlways` marker inside the
// contract class body that is not in the leading comments of the member kind
// that reads it (method / property) is refused with the shared message, located
// at the marker's `@` (1-based line, 0-based byte column).
//
// Proves: the Go TS-surface parser refuses each lost-directive shape the TS
// reference refuses (sighash-parse.test.ts, "N-199"), with the same text and
// location, and still accepts attached directives and prose outside the class.
// Does not prove: cross-tier agreement (conformance/negatives/
// n199-lost-directive-parity.test.ts does) or non-ASCII column units.
func TestN199_LostDirectiveRefused(t *testing.T) {
	const stateful = "import { StatefulSmartContract } from 'runar-lang';\nexport class C extends StatefulSmartContract {\n  n: bigint;\n  constructor(n: bigint) { super(n); this.n = n; }\n%s\n}\n"
	const bump = "  public bump(): void { this.addOutput(1000n, this.n); }"
	cases := []struct{ name, src, marker string }{
		{"line comment sharing a line with the preceding method", fmt.Sprintf(stateful, "  private foo(): void {} // @sighash SINGLE|FORKID\n"+bump), "@sighash"},
		{"JSDoc sharing a line with the preceding method", fmt.Sprintf(stateful, "  private foo(): void {} /** @sighash SINGLE|FORKID */\n"+bump), "@sighash"},
		{"end of class body", fmt.Sprintf(stateful, bump+"\n  /** @sighash SINGLE|FORKID */"), "@sighash"},
		{"inside a method body", fmt.Sprintf(stateful, "  public bump(): void {\n    // @sighash SINGLE|FORKID\n    this.addOutput(1000n, this.n);\n  }"), "@sighash"},
		{"on a property", fmt.Sprintf(stateful, "  /** @sighash SINGLE|FORKID */\n  readonly k: bigint = 1n;\n"+bump), "@sighash"},
		{"above the constructor", "import { StatefulSmartContract } from 'runar-lang';\nexport class C extends StatefulSmartContract {\n  n: bigint;\n  /** @sighash SINGLE|FORKID */\n  constructor(n: bigint) { super(n); this.n = n; }\n" + bump + "\n}\n", "@sighash"},
		{"@embedAlways sharing a line with the preceding property", "import { SmartContract, assert } from 'runar-lang';\nexport class C extends SmartContract {\n  readonly a: bigint; // @embedAlways\n  readonly tag: bigint;\n  constructor(a: bigint, tag: bigint) { super(a, tag); this.a = a; this.tag = tag; }\n  public go(x: bigint): void { assert(x == this.a); }\n}\n", "@embedAlways"},
		{"@embedAlways on a method", "import { SmartContract, assert } from 'runar-lang';\nexport class C extends SmartContract {\n  readonly a: bigint;\n  constructor(a: bigint) { super(a); this.a = a; }\n  /** @embedAlways */\n  public go(x: bigint): void { assert(x == this.a); }\n}\n", "@embedAlways"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			res := ParseSource([]byte(c.src), "X.runar.ts")
			idx := strings.Index(c.src, c.marker)
			wantLine := strings.Count(c.src[:idx], "\n") + 1
			wantCol := idx - (strings.LastIndex(c.src[:idx], "\n") + 1)
			if len(res.Errors) != 1 {
				t.Fatalf("errors = %v, want exactly one lost-directive refusal", res.ErrorStrings())
			}
			e := res.Errors[0]
			if e.Message != LostDirectiveMsg(c.marker) || e.Loc == nil || e.Loc.Line != wantLine || e.Loc.Column != wantCol {
				t.Fatalf("got %q at %v, want %q at %d:%d", e.Message, e.Loc, LostDirectiveMsg(c.marker), wantLine, wantCol)
			}
		})
	}

	control := "import { StatefulSmartContract } from 'runar-lang';\n// File header prose: this contract uses @sighash SINGLE|FORKID and @embedAlways.\n/** Class doc: `@sighash` lives on bump, `@embedAlways` on tag. */\nexport class C extends StatefulSmartContract {\n  n: bigint;\n  /** @embedAlways */\n  readonly tag: bigint;\n  constructor(n: bigint, tag: bigint) { super(n, tag); this.n = n; this.tag = tag; }\n  private foo(): void {}\n  // @sighash SINGLE|FORKID\n" + bump + "\n}\n"
	if m := sighashMethodByName(t, control, "bump"); m.SighashType == nil || *m.SighashType != 0x43 {
		t.Fatalf("control: SighashType = %v, want 0x43", m.SighashType)
	}
}

func anyErrContains(res *ParseResult, sub string) bool {
	for _, e := range res.Errors {
		if strings.Contains(e.Message, sub) {
			return true
		}
	}
	return false
}
