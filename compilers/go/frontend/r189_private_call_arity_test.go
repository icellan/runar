package frontend

import (
	"fmt"
	"strings"
	"testing"
)

// R-189 — a private method may shadow a builtin, and nothing upstream of ANF
// lowering notices when the two disagree about arity.
//
// `typecheck.go` resolves a BARE-IDENTIFIER call against `builtinFunctions`
// BEFORE it looks at the contract's own methods; `anf_lower.go` resolves the
// same call against private methods FIRST. So `min(x, y)` against
// `private min(a, b, c)` type-checks as the two-argument BUILTIN `min` and
// then lowers as the three-parameter METHOD `min`. No validator forbids the
// shadowing.
//
// The zip that bound params to args stopped at the shorter list, so:
//   - the surplus parameter `c` was left unbound. If the body READ it, the
//     defect surfaced two passes later as "method parameter 'c' is not on the
//     stack" — a stack-lowering message about a pass the author never wrote in.
//   - if the body did NOT read it, the contract compiled clean: an arity
//     mismatch silently accepted (measured: exit 0, 1373 bytes of script).
//   - an EXTRA argument was evaluated and then dropped on the floor, also
//     silently (measured: exit 0).
//
// Every call form and both lowering paths (inlined / method_call) are covered
// below. These sources must reach ANF lowering — the helper asserts parse,
// validate and typecheck all pass first, so a future fix upstream turns these
// into a loud failure here rather than a silent no-op.

// Output-emitting helper => shouldInlinePrivate is true => the INLINED path.
const r189InlinedTooFewArgs = `
class R189Inlined extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private min(a: bigint, b: bigint, c: bigint): bigint {
    this.count = a + b + c;
    this.addOutput(1000n, this.count);
    return a;
  }

  public go(x: bigint, y: bigint) {
    min(x, y);
  }
}
`

// Same, but the surplus parameter is never read: this one used to COMPILE.
const r189InlinedSurplusParamUnread = `
class R189InlinedUnread extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private min(a: bigint, b: bigint, c: bigint): bigint {
    this.count = a + b;
    this.addOutput(1000n, this.count);
    return a;
  }

  public go(x: bigint, y: bigint) {
    min(x, y);
  }
}
`

// Too MANY arguments: the extra one was evaluated and discarded.
const r189InlinedTooManyArgs = `
class R189InlinedExtra extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private min(a: bigint): bigint {
    this.count = a;
    this.addOutput(1000n, this.count);
    return a;
  }

  public go(x: bigint, y: bigint) {
    min(x, y);
  }
}
`

// Mutation-only helper => shouldInlinePrivate is false => the method_call
// path, which hands the same mismatch to stack lowering instead.
const r189MethodCallPath = `
class R189MethodCall extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private min(a: bigint, b: bigint, c: bigint): bigint {
    this.count = a + b;
    return a;
  }

  public go(x: bigint, y: bigint) {
    min(x, y);
    this.addOutput(1000n, this.count);
  }
}
`

// `this.min(x, y)` — the PropertyAccess call form. Typecheck DOES resolve
// `this.X(...)` against the contract's own method signatures, so this form is
// already refused in pass 3; the hole is specific to the bare identifier.
// Pinned so a future typecheck change that drops the check is caught here.
const r189ThisCallForm = `
class R189ThisForm extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private min(a: bigint, b: bigint, c: bigint): bigint {
    this.count = a + b;
    this.addOutput(1000n, this.count);
    return a;
  }

  public go(x: bigint, y: bigint) {
    this.min(x, y);
  }
}
`

// Control 1: the SAME builtin-shadowing private, called at the method's real
// arity through `this.` (the bare form cannot reach pass 4 at arity 3 — pass 3
// checks it against the two-argument BUILTIN `min` and refuses). Must lower.
const r189ControlShadowingAtRealArity = `
class R189ControlShadow extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private min(a: bigint, b: bigint, c: bigint): bigint {
    this.count = a + b + c;
    this.addOutput(1000n, this.count);
    return a;
  }

  public go(x: bigint, y: bigint, z: bigint) {
    this.min(x, y, z);
  }
}
`

// Control 2: an ordinary private helper (no builtin shadowing), bare-identifier
// call at matching arity — the Move / Go-DSL lowering path this refusal sits
// directly on. Must lower. Without these two controls a refusal that simply
// rejected every private call would pass every test above.
const r189ControlPlainPrivate = `
class R189ControlPlain extends StatefulSmartContract {
  count: bigint;

  constructor(count: bigint) {
    super(count);
    this.count = count;
  }

  private tally(a: bigint, b: bigint): bigint {
    this.count = a + b;
    this.addOutput(1000n, this.count);
    return a;
  }

  public go(x: bigint, y: bigint) {
    tally(x, y);
  }
}
`

// r189Frontend runs passes 1-4 and reports what refused, and where. A test
// that asserted only "it fails" could not tell a pass-3 refusal from a pass-4
// one — which is the whole subject here.
func r189Frontend(t *testing.T, source string) (typecheckErrs []string, lowerMsg string) {
	t.Helper()

	parsed := ParseSource([]byte(source), "test.runar.ts")
	if len(parsed.Errors) > 0 {
		t.Fatalf("parse errors: %s", strings.Join(parsed.ErrorStrings(), "; "))
	}
	if val := Validate(parsed.Contract); len(val.Errors) > 0 {
		t.Fatalf("validation errors: %s", strings.Join(val.ErrorStrings(), "; "))
	}
	if tc := TypeCheck(parsed.Contract); len(tc.Errors) > 0 {
		return tc.ErrorStrings(), ""
	}

	defer func() {
		if r := recover(); r != nil {
			lowerMsg = fmt.Sprint(r)
		}
	}()
	LowerToANF(parsed.Contract)
	return nil, ""
}

func TestR189PrivateCallArityIsRefused(t *testing.T) {
	cases := []struct {
		name   string
		source string
		want   string
	}{
		{"inlined path, too few args", r189InlinedTooFewArgs,
			"private method 'min' expects 3 argument(s), got 2."},
		{"inlined path, surplus param never read", r189InlinedSurplusParamUnread,
			"private method 'min' expects 3 argument(s), got 2."},
		{"inlined path, too many args", r189InlinedTooManyArgs,
			"private method 'min' expects 1 argument(s), got 2."},
		{"method_call path", r189MethodCallPath,
			"private method 'min' expects 3 argument(s), got 2."},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tcErrs, got := r189Frontend(t, tc.source)
			if len(tcErrs) > 0 {
				t.Fatalf("pass 3 refused this form, so pass 4 never saw it — the "+
					"case no longer tests what it claims: %s", strings.Join(tcErrs, "; "))
			}
			if got == "" {
				t.Fatalf("arity mismatch was accepted: ANF lowering produced a program")
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("refusal does not name the mismatch:\n  got:  %s\n  want: %s", got, tc.want)
			}
		})
	}
}

// `this.min(x, y)` never reaches pass 4: typecheck resolves `this.X(...)`
// against the contract's own method signatures. Pinned so that if that ever
// changes, the pass-4 guard above is known to be the only thing left.
func TestR189ThisCallFormIsRefusedByTypecheck(t *testing.T) {
	tcErrs, lowerMsg := r189Frontend(t, r189ThisCallForm)
	if len(tcErrs) == 0 {
		t.Fatalf("expected a pass-3 refusal for this.min(x, y); pass 4 said %q", lowerMsg)
	}
	if !strings.Contains(strings.Join(tcErrs, "; "), "min() expects 3 argument(s), got 2") {
		t.Fatalf("unexpected typecheck errors: %s", strings.Join(tcErrs, "; "))
	}
}

func TestR189MatchingArityStillLowers(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
	}{
		{"builtin-shadowing private at its real arity", r189ControlShadowingAtRealArity},
		{"plain private helper, bare-identifier call", r189ControlPlainPrivate},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tcErrs, msg := r189Frontend(t, tc.source)
			if len(tcErrs) > 0 {
				t.Fatalf("control must type-check: %s", strings.Join(tcErrs, "; "))
			}
			if msg != "" {
				t.Fatalf("control must still lower, got refusal: %s", msg)
			}
		})
	}
}
