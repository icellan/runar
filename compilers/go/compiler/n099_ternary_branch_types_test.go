package compiler

// N-099 — a ternary whose two arms have incompatible types.
//
//	const y: ByteString = f ? this.blob : x;   // blob: ByteString, x: bigint
//
// Measured across the seven tiers before the fix:
//
//	ts / rust / java          REJECT
//	go / python / zig / ruby  ACCEPT, 12 hexchars
//
// This tier silently took the CONSEQUENT's type as the expression's type. A
// ByteString and a bigint do not share a stack representation — one is a byte
// string, the other a script number — so the arm that was silently retyped
// leaves the wrong kind of value on the stack and everything downstream reads a
// type the author never wrote. Same class as the operand-position <unknown>
// escapes R-092 closed: a 33-byte push into an arithmetic opcode succeeds
// post-Genesis and computes something meaningless rather than failing.
//
// The fall-through this rule needs was already here — `isSubtype(alt, cons) ||
// isSubtype(cons, alt)` — it returned `consType` from it instead of raising.
// Ported from the TypeScript reference (Rust already carries it verbatim),
// wording included. The neighbouring "ternary condition must be boolean"
// message is lowercase in this tier's house style while TS capitalises it;
// that pre-existing casing divergence is left alone rather than widened, and
// the NEW message matches TS exactly so the seven tiers agree on it.
//
// The tier's own isSubtype is used, deliberately, rather than a bespoke
// predicate. It is narrower than TS's (it lacks the both-sides-in-one-family
// clauses), which is a SEPARATE and already-live divergence — `const h: Sha256
// = this.pkh` is accepted by ts/rust/zig and rejected by go/python/ruby/java
// today, with no ternary involved. Using a different relation here would have
// made this tier internally inconsistent to hide that; it is reported instead.

import (
	"strings"
	"testing"
)

const n099Head = `import { SmartContract, ByteString, Ripemd160, assert, hash160 } from 'runar-lang';

class C extends SmartContract {
  readonly pkh: Ripemd160;
  readonly blob: ByteString;

  constructor(pkh: Ripemd160, blob: ByteString) {
    super(pkh, blob);
    this.pkh = pkh;
    this.blob = blob;
  }

  private anySats(): bigint { return 1n; }

`

func n099Contract(body string) string {
	return n099Head + body + "}\n"
}

// --- REJECT ----------------------------------------------------------------

var n099MixedArms = n099Contract(`  public go(x: bigint, f: boolean) {
    const y: ByteString = f ? this.blob : x;
    assert(y == this.blob);
  }
`)

// The mirror image. A rule that only looked one way would let this through.
var n099MixedArmsSwapped = n099Contract(`  public go(x: bigint, f: boolean) {
    const y: bigint = f ? x : this.blob;
    assert(y > 0n);
  }
`)

// --- ACCEPT (over-rejection guards) ----------------------------------------

var n099SameTypeArms = n099Contract(`  public go(x: bigint, f: boolean) {
    const a: bigint = f ? x : 2n;
    assert(a > 0n);
  }
`)

// `Ripemd160` is a declared subtype of `ByteString`; isSubtype relates them and
// the rule must not fire.
var n099SubtypeArms = n099Contract(`  public go(x: bigint, f: boolean) {
    const b: ByteString = f ? this.blob : this.pkh;
    assert(hash160(b) != this.pkh || x > 0n);
  }
`)

// A private helper's declared return type is discarded at parse time in EVERY
// tier, so this arm infers as <unknown> — top of the subtype lattice, hence
// related to everything. Must stay ACCEPTED.
var n099UnknownArm = n099Contract(`  public go(x: bigint, f: boolean) {
    const c: bigint = f ? this.anySats() : x;
    assert(c > 0n);
  }
`)

func TestN099_RejectsIncompatibleTernaryArms(t *testing.T) {
	n099RequireDiagnostic(t, n099MixedArms,
		"Ternary branches have incompatible types: 'ByteString' and 'bigint'")
}

func TestN099_RejectsTheSwappedShapeToo(t *testing.T) {
	n099RequireDiagnostic(t, n099MixedArmsSwapped,
		"Ternary branches have incompatible types: 'bigint' and 'ByteString'")
}

func TestN099_AcceptedTernaryArms(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
	}{
		{"identical arm types", n099SameTypeArms},
		{"a declared subtype pair (ByteString / Ripemd160)", n099SubtypeArms},
		{"an arm inferred as <unknown>", n099UnknownArm},
	} {
		t.Run(tc.name, func(t *testing.T) {
			res := CompileFromSourceStrWithResult(tc.source, "C.runar.ts")
			if !res.Success {
				t.Fatalf("expected this contract to compile; diagnostics: %v", n099Errors(tc.source))
			}
			if res.ScriptHex == "" {
				t.Fatalf("compiled to an empty script")
			}
		})
	}
}

func n099Errors(source string) []string {
	res := CompileFromSourceStrWithResult(source, "C.runar.ts")
	var out []string
	for _, d := range res.Diagnostics {
		if d.Severity == "error" {
			out = append(out, d.FormatMessage())
		}
	}
	return out
}

func n099RequireDiagnostic(t *testing.T, source, want string) {
	t.Helper()
	errs := n099Errors(source)
	for _, e := range errs {
		if strings.Contains(e, want) {
			return
		}
	}
	t.Fatalf("expected a diagnostic containing %q; got %v", want, errs)
}
