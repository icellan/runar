package compiler

import (
	"strings"
	"testing"
)

// R-039 — irregular Python builtin aliases must map identically in all 7 tiers.
//
// Python contracts are written in snake_case and every tier's `.runar.py`
// parser rewrites the identifiers to the canonical Rúnar camelCase names. Most
// names fall out of a mechanical snake→camel rule, but five do not and
// therefore need an explicit entry in each tier's special-name table:
//
//	int_to_str           -> int2str            (digit: "to" collapses to "2")
//	safe_div             -> safediv            (no interior capital)
//	safe_mod             -> safemod            (no interior capital)
//	div_mod              -> divmod             (no interior capital)
//	require_output_p2pkh -> requireOutputP2PKH (all-caps PKH token)
//
// Before this test the Go tier had safe_div/safe_mod/div_mod but neither
// int_to_str nor require_output_p2pkh: the mechanical rule produced `intToStr`
// and `requireOutputP2pkh`, which the type checker rejects as unknown
// functions, while the Python tier compiled the very same source. CLAUDE.md
// makes frontend parity a no-exceptions invariant, so that is a parity break.
//
// The pinned hexes are the SEVEN-TIER agreed fold-OFF output.

const pyInt2StrSnakeSource = `
from runar import SmartContract, Bigint, ByteString, public, assert_, int_to_str, len_


class Encoder(SmartContract):
    n: Bigint

    def __init__(self, n: Bigint):
        super().__init__(n)
        self.n = n

    @public
    def unlock(self):
        out: ByteString = int_to_str(self.n, 4)
        assert_(len_(out) == 4)
`

const pyMathAliasesSource = `
from runar import SmartContract, Bigint, public, assert_


class Aliases(SmartContract):
    n: Bigint

    def __init__(self, n: Bigint):
        super().__init__(n)
        self.n = n

    @public
    def unlock(self):
        a: Bigint = safe_div(self.n, 3)
        b: Bigint = safe_mod(self.n, 3)
        c: Bigint = div_mod(self.n, 3)
        assert_(a + b + c > 0)
`

const pyIntentSnakeSource = `
from runar import (
    StatefulSmartContract, ByteString, Bigint, Readonly, public,
)


class Intent(StatefulSmartContract):
    bondPKH: Readonly[ByteString]
    bondAmount: Readonly[Bigint]
    count: Bigint

    def __init__(self, bondPKH: ByteString, bondAmount: Bigint, count: Bigint):
        super().__init__(bondPKH, bondAmount, count)
        self.bondPKH = bondPKH
        self.bondAmount = bondAmount
        self.count = count

    @public
    def payBond(self):
        require_output_p2pkh(0, self.bondPKH, self.bondAmount)
`

const pyUnknownBuiltinSource = `
from runar import SmartContract, Bigint, public, assert_


class Unknown(SmartContract):
    n: Bigint

    def __init__(self, n: Bigint):
        super().__init__(n)
        self.n = n

    @public
    def unlock(self):
        assert_(not_a_builtin(self.n) > 0)
`

func pyAliasHex(t *testing.T, source, fileName string) string {
	t.Helper()
	res := CompileFromSourceStrWithResult(source, fileName, CompileOptions{DisableConstantFolding: true})
	if !res.Success {
		t.Fatalf("compilation of %s failed: %v", fileName, res.Diagnostics)
	}
	return res.ScriptHex
}

func TestR039_IntToStr_SevenTierScript(t *testing.T) {
	got := pyAliasHex(t, pyInt2StrSnakeSource, "Encoder.runar.py")
	if got != "0054808277549c" {
		t.Errorf("int_to_str script diverged from the seven-tier output:\n  got:  %s\n  want: 0054808277549c", got)
	}
}

func TestR039_MathAliases_SevenTierScript(t *testing.T) {
	const want = "00537692699600537692699700536e967b7b97757b7b937c9300a0"
	got := pyAliasHex(t, pyMathAliasesSource, "Aliases.runar.py")
	if got != want {
		t.Errorf("safe_div/safe_mod/div_mod script diverged from the seven-tier output:\n  got:  %s\n  want: %s", got, want)
	}
}

func TestR039_RequireOutputP2PKH_MatchesCamelCase(t *testing.T) {
	camel := strings.Replace(pyIntentSnakeSource, "require_output_p2pkh", "requireOutputP2PKH", 1)
	if pyAliasHex(t, pyIntentSnakeSource, "Intent.runar.py") != pyAliasHex(t, camel, "Intent.runar.py") {
		t.Error("require_output_p2pkh did not lower byte-identically to requireOutputP2PKH")
	}
}

func TestR039_UnknownSnakeCaseFunctionStillRejected(t *testing.T) {
	// Guards against the lazy fix: a blanket pass-through that maps any
	// snake_case identifier onto a builtin name would let this compile.
	res := CompileFromSourceStrWithResult(pyUnknownBuiltinSource, "Unknown.runar.py", CompileOptions{DisableConstantFolding: true})
	if res.Success {
		t.Fatal("expected not_a_builtin() to be rejected, but compilation succeeded")
	}
	joined := ""
	for _, d := range res.Diagnostics {
		joined += d.Message + "\n"
	}
	if !strings.Contains(joined, "notABuiltin") {
		t.Errorf("expected an unknown-function diagnostic for notABuiltin, got:\n%s", joined)
	}
}
