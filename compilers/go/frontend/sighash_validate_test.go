package frontend

import (
	"strings"
	"testing"
)

// #123 field-usage validation (security core) — one rejection per unsound case,
// ported from sighash-validate.test.ts (incl. the e88f202c security fixes).

func sighashErrors(t *testing.T, src string) []string {
	t.Helper()
	res := ParseSource([]byte(src), "X.runar.ts")
	if len(res.Errors) > 0 {
		return res.ErrorStrings() // parse-level errors (e.g. FORKID guard) count
	}
	vr := Validate(res.Contract)
	return vr.ErrorStrings()
}

func sighashWarnings(t *testing.T, src string) []string {
	t.Helper()
	res := ParseSource([]byte(src), "X.runar.ts")
	if len(res.Errors) > 0 {
		t.Fatalf("unexpected parse errors: %v", res.ErrorStrings())
	}
	return Validate(res.Contract).WarningStrings()
}

func anyContains(xs []string, sub string) bool {
	for _, x := range xs {
		if strings.Contains(x, sub) {
			return true
		}
	}
	return false
}

// ---- ANYONECANPAY ---------------------------------------------------------

func TestSighashValidate_ACP_RejectsHashPrevouts(t *testing.T) {
	src := `
    class Guard extends SmartContract {
      readonly expected: ByteString;
      constructor(expected: ByteString) { super(expected); this.expected = expected; }
      /** @sighash ALL|ANYONECANPAY|FORKID */
      public spend(pre: SigHashPreimage): void {
        assert(checkPreimage(pre));
        assert(extractHashPrevouts(pre) === this.expected);
      }
    }`
	if !anyContains(sighashErrors(t, src), "hashPrevouts") {
		t.Fatalf("want hashPrevouts/ANYONECANPAY reject, got %v", sighashErrors(t, src))
	}
}

func TestSighashValidate_ACP_RejectsPrevOutputScript(t *testing.T) {
	src := `
    class Co extends StatefulSmartContract {
      readonly h0: ByteString;
      n: bigint;
      constructor(h0: ByteString, n: bigint) { super(h0, n); this.h0 = h0; this.n = n; }
      /** @sighash ALL|ANYONECANPAY|FORKID */
      public coSpend(): void {
        const s = extractPrevOutputScript(1n, this.h0);
        assert(len(s) > 0n);
      }
    }`
	errs := sighashErrors(t, src)
	if !anyContains(errs, "companion input") && !anyContains(errs, "prevout script") {
		t.Fatalf("want companion-input/prevout-script reject, got %v", errs)
	}
}

func TestSighashValidate_ACP_AcceptsUnderALLDefault(t *testing.T) {
	src := `
    class Guard extends SmartContract {
      readonly expected: ByteString;
      constructor(expected: ByteString) { super(expected); this.expected = expected; }
      public spend(pre: SigHashPreimage): void {
        assert(checkPreimage(pre));
        assert(extractHashPrevouts(pre) === this.expected);
      }
    }`
	if errs := sighashErrors(t, src); len(errs) != 0 {
		t.Fatalf("ALL default should accept, got %v", errs)
	}
}

// ---- NONE -----------------------------------------------------------------

func TestSighashValidate_NONE_RejectsContinuation(t *testing.T) {
	src := `
    class Counter extends StatefulSmartContract {
      n: bigint;
      constructor(n: bigint) { super(n); this.n = n; }
      /** @sighash NONE|FORKID */
      public bump(): void { this.n = this.n + 1n; }
    }`
	errs := sighashErrors(t, src)
	if !anyContains(errs, "NONE commits to NO outputs") && !anyContains(errs, "continuation") {
		t.Fatalf("want NONE-continuation reject, got %v", errs)
	}
}

// ---- SINGLE ---------------------------------------------------------------

// D25: the #123 (F1) refusal predated the F-024 `_newAmount` floor and
// N-038; SINGLE hashes the whole same-index output, value included, so a
// mutate-only SINGLE continuation is sound (and the default for a contract
// whose continuation methods are all mutate-only).
func TestSighashValidate_SINGLE_AcceptsMutateOnlyContinuation(t *testing.T) {
	src := `
    class Counter extends StatefulSmartContract {
      n: bigint;
      constructor(n: bigint) { super(n); this.n = n; }
      /** @sighash SINGLE|FORKID */
      public bump(): void { this.n = this.n + 1n; }
    }`
	if errs := sighashErrors(t, src); len(errs) != 0 {
		t.Fatalf("a mutate-only SINGLE continuation must be accepted, got %v", errs)
	}
}

func TestSighashValidate_SINGLE_RejectsMultiOutput(t *testing.T) {
	src := `
    class Multi extends StatefulSmartContract {
      count: bigint;
      constructor(count: bigint) { super(count); this.count = count; }
      /** @sighash SINGLE|FORKID */
      public split(): void {
        this.addOutput(1000n, this.count);
        this.addOutput(2000n, this.count);
      }
    }`
	if !anyContains(sighashErrors(t, src), "SINGLE commits ONLY to the output at this input") {
		t.Fatalf("want multi-output SINGLE reject, got %v", sighashErrors(t, src))
	}
}

// F1: explicit single addOutput is ALLOWED but warns.
func TestSighashValidate_SINGLE_AcceptsExplicitSingleWithWarning(t *testing.T) {
	src := `
    class Pay extends StatefulSmartContract {
      n: bigint;
      constructor(n: bigint) { super(n); this.n = n; }
      /** @sighash SINGLE|FORKID */
      public settle(): void { this.addOutput(1000n, this.n); }
    }`
	if errs := sighashErrors(t, src); len(errs) != 0 {
		t.Fatalf("explicit single addOutput should compile, got %v", errs)
	}
	warns := sighashWarnings(t, src)
	if !anyContains(warns, "SINGLE commits ONLY to the output at this input") &&
		!anyContains(warns, "carries the FULL protected value") {
		t.Fatalf("want value-pinning warning, got %v", warns)
	}
}

// F4: requireOutputP2PKH under SINGLE is rejected.
func TestSighashValidate_SINGLE_RejectsRequireOutputP2PKH(t *testing.T) {
	src := `
    class Cov extends StatefulSmartContract {
      readonly bondPKH: ByteString;
      readonly bond: bigint;
      constructor(bondPKH: ByteString, bond: bigint) { super(bondPKH, bond); this.bondPKH = bondPKH; this.bond = bond; }
      /** @sighash SINGLE|FORKID */
      public payBond() { requireOutputP2PKH(0n, this.bondPKH, this.bond); }
    }`
	if !anyContains(sighashErrors(t, src), "'requireOutputP2PKH' asserts an output at a fixed index") {
		t.Fatalf("want requireOutputP2PKH/SINGLE reject, got %v", sighashErrors(t, src))
	}
}

// F2 (parse-level): a FORKID-less flag set is rejected up front.
func TestSighashValidate_RejectsMissingForkID(t *testing.T) {
	src := `
    class Counter extends StatefulSmartContract {
      n: bigint;
      constructor(n: bigint) { super(n); this.n = n; }
      /** @sighash SINGLE */
      public bump(): void { this.addOutput(1000n, this.n); }
    }`
	if !anyContains(sighashErrors(t, src), "FORKID is mandatory on BSV") {
		t.Fatalf("want FORKID-mandatory reject, got %v", sighashErrors(t, src))
	}
}

// F3: a forbidden read hidden in a for-loop CONDITION under NONE is caught.
func TestSighashValidate_F3_LoopConditionHiddenRead(t *testing.T) {
	src := `
    class C extends SmartContract {
      readonly expected: ByteString;
      constructor(expected: ByteString) { super(expected); this.expected = expected; }
      /** @sighash NONE|FORKID */
      public spend(pre: SigHashPreimage): void {
        for (let i = 0n; i < 3n && extractOutputHash(pre) === this.expected; i++) { assert(i < 2n); }
        assert(checkPreimage(pre));
      }
    }`
	if !anyContains(sighashErrors(t, src), "hashOutputs") {
		t.Fatalf("want hashOutputs/NONE reject from loop condition, got %v", sighashErrors(t, src))
	}
}

// Default (no directive) must never be flagged.
func TestSighashValidate_DefaultNeverFlagged(t *testing.T) {
	src := `
    class Counter extends StatefulSmartContract {
      n: bigint;
      constructor(n: bigint) { super(n); this.n = n; }
      public bump(): void { this.n = this.n + 1n; }
    }`
	if errs := sighashErrors(t, src); len(errs) != 0 {
		t.Fatalf("default mode should never be flagged, got %v", errs)
	}
}
