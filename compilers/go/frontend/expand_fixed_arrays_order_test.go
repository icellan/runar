package frontend

import (
	"strings"
	"testing"
)

// N-048 (external "PrematurePeek"): pass 3b hoists a computed FixedArray index
// to `const __idx_K` in front of its whole statement. In
//
//	assert(++this.cursor > 0n && this.enabled[this.cursor % 2n] === 1n);
//
// that bound the index BEFORE the increment, so the gate read the
// pre-increment slot (an outsider spend at cursor 0 was accepted under the
// real @bsv/sdk Spend). The AST has no let-expression, so every hoist that
// would reorder evaluation is refused with the diagnostic shared by all seven
// tiers.
//
// Proves: the same refused / accepted shapes as the TS reference
// (packages/runar-compiler/src/__tests__/03b-expand-fixed-arrays.test.ts).
// Does not prove on-chain behaviour; the TS VM test and
// conformance/negatives/N120-N122 cover that across tiers.

const hoistOrderDiag = "FixedArray index would be evaluated out of source order"

func n048Expand(t *testing.T, body string) (*ContractNode, []Diagnostic) {
	t.Helper()
	src := `
class Peek extends StatefulSmartContract {
  readonly enabled: FixedArray<bigint, 2> = [1n, 0n];
  slots: FixedArray<bigint, 2> = [0n, 0n];
  cursor: bigint;
  constructor(cursor: bigint) { super(cursor); this.cursor = cursor; }
  public release(k: bigint, c: boolean) {
    ` + body + `
  }
}
`
	pr := ParseSource([]byte(src), "Peek.runar.ts")
	if len(pr.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(pr.ErrorStrings(), "; "))
	}
	res := ExpandFixedArrays(pr.Contract)
	return res.Contract, res.Errors
}

func n048Joined(errs []Diagnostic) string {
	msgs := make([]string, len(errs))
	for i, e := range errs {
		msgs[i] = e.Message
	}
	return strings.Join(msgs, "\n")
}

func TestExpandFixedArrays_N048_RefusesReorderingHoist(t *testing.T) {
	cases := []struct{ what, body string }{
		{"the reported shape", "assert(++this.cursor > 0n && this.enabled[this.cursor % 2n] === 1n);"},
		{"index after an earlier ++", "assert(++this.cursor + this.enabled[this.cursor % 2n] > 0n);"},
		{"index after an output intrinsic", `assert(this.addRawOutput(1n, toByteString("00")) === this.enabled[this.cursor % 2n]);`},
		{"right operand of &&", "assert(k > 0n && this.enabled[k - 1n] === 1n);"},
		{"right operand of ||", "assert(k === 0n || this.enabled[k - 1n] === 1n);"},
		{"ternary arm", "assert((c ? this.enabled[k + 1n] : 0n) === 0n);"},
		{"own ++ ahead of an earlier read", "assert(this.cursor + this.enabled[++this.cursor % 2n] > 0n);"},
		{"value read after target-index effect", "this.slots[++this.cursor % 2n] = this.enabled[this.cursor % 2n]; assert(true);"},
	}
	for _, tc := range cases {
		t.Run(tc.what, func(t *testing.T) {
			_, errs := n048Expand(t, tc.body)
			if !strings.Contains(n048Joined(errs), hoistOrderDiag) {
				t.Fatalf("expected the hoist-order refusal, got %q", n048Joined(errs))
			}
		})
	}
}

func TestExpandFixedArrays_N048_AcceptsOrderPreservingHoist(t *testing.T) {
	cases := []struct{ what, body string }{
		{"increment in its own statement", "++this.cursor; assert(this.enabled[this.cursor % 2n] === 1n);"},
		{"left operand of &&", "assert(this.enabled[k - 1n] === 1n && k > 0n);"},
		{"ternary condition", "assert((this.enabled[k + 1n] === 1n ? 1n : 0n) === 1n);"},
		{"effect after the read", "assert(this.enabled[this.cursor % 2n] + ++this.cursor > 0n);"},
		{"statement-form read", "const v = this.enabled[k + 1n]; assert(v === 1n);"},
		{"computed write index, effectful value", "this.slots[this.cursor % 2n] = ++this.cursor; assert(true);"},
	}
	for _, tc := range cases {
		t.Run(tc.what, func(t *testing.T) {
			_, errs := n048Expand(t, tc.body)
			if strings.Contains(n048Joined(errs), hoistOrderDiag) {
				t.Fatalf("unexpected hoist-order refusal: %q", n048Joined(errs))
			}
		})
	}
}

func TestExpandFixedArrays_N048_SplitFormHoistsAfterIncrement(t *testing.T) {
	c, errs := n048Expand(t, "++this.cursor; assert(this.enabled[this.cursor % 2n] === 1n);")
	if len(errs) > 0 {
		t.Fatalf("unexpected errors: %s", n048Joined(errs))
	}
	m := findMethod(c, "release")
	if _, ok := m.Body[0].(ExpressionStmt); !ok {
		t.Fatalf("body[0] = %T, want ExpressionStmt", m.Body[0])
	}
	decl, ok := m.Body[1].(VariableDeclStmt)
	if !ok || !strings.HasPrefix(decl.Name, "__idx_") {
		t.Fatalf("body[1] = %#v, want the __idx_* binding", m.Body[1])
	}
}
