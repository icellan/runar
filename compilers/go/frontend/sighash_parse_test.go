package frontend

import (
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
	m := sighashMethodByName(t, src, "bump")
	if m.SighashType != nil {
		t.Fatalf("SighashType = %v, want nil (default) — ts-morph drops a same-line-as-preceding-token directive", *m.SighashType)
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
