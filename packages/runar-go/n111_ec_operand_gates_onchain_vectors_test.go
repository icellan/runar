package runar

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

// N-111: the Go native EC builtins (what a .runar.go contract calls under
// `go test`) must apply the compiled script's operand gates — EcAdd /
// EcNegate: 64 bytes and x, y < p (R-117); EcMul: on-curve or the all-zero
// identity O (R-157); EcPointX / EcPointY / EcEncodeCompressed: width only —
// and its addition law (R-053: P + O = P; x1 == x2 with y1 != y2 is O).
//
// Oracle: packages/runar-zig/src/fixtures/n111-ec-operand-gates-onchain.json,
// every row executed on @bsv/sdk Spend.validate by
// packages/runar-testing/src/__tests__/n111-ec-operand-gates-onchain.test.ts.
//
// Proves: for every row, each builtin returns the on-chain value, or panics
// where the script aborts (never a value).
// Does not prove: inputs outside the file, or the script itself.

type n111Row struct {
	Fn     string `json:"fn"`
	P      string `json:"p"`
	Q      string `json:"q"`
	K      string `json:"k"`
	Expect string `json:"expect"`
	Why    string `json:"why"`
}

func n111Rows(t *testing.T) []n111Row {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)
	var path string
	for {
		candidate := filepath.Join(dir, "packages", "runar-zig", "src", "fixtures", "n111-ec-operand-gates-onchain.json")
		if _, err := os.Stat(candidate); err == nil {
			path = candidate
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate n111-ec-operand-gates-onchain.json walking up from %s", filepath.Dir(thisFile))
		}
		dir = parent
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []n111Row `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Cases
}

func n111Point(t *testing.T, h string) Point {
	t.Helper()
	b, err := hex.DecodeString(h)
	if err != nil {
		t.Fatal(err)
	}
	return Point(b)
}

// n111Run returns the builtin's result rendered like the vector's `expect`
// (hex for bytes, decimal for an integer), or panicked = true.
func n111Run(t *testing.T, r n111Row) (got string, panicked bool) {
	t.Helper()
	defer func() {
		if rec := recover(); rec != nil {
			got, panicked = fmt.Sprint(rec), true
		}
	}()
	k := int64(0)
	if r.K != "" {
		v, err := strconv.ParseInt(r.K, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		k = v
	}
	switch r.Fn {
	case "ecAdd":
		return hex.EncodeToString([]byte(EcAdd(n111Point(t, r.P), n111Point(t, r.Q)))), false
	case "ecMul":
		return hex.EncodeToString([]byte(EcMul(n111Point(t, r.P), k))), false
	case "ecMulGen":
		return hex.EncodeToString([]byte(EcMulGen(k))), false
	case "ecNegate":
		return hex.EncodeToString([]byte(EcNegate(n111Point(t, r.P)))), false
	case "ecPointX":
		return (*big.Int)(EcPointX(n111Point(t, r.P))).String(), false
	case "ecPointY":
		return (*big.Int)(EcPointY(n111Point(t, r.P))).String(), false
	case "ecEncodeCompressed":
		return hex.EncodeToString([]byte(EcEncodeCompressed(n111Point(t, r.P)))), false
	case "ecOnCurve":
		return strconv.FormatBool(EcOnCurve(n111Point(t, r.P))), false
	}
	t.Fatalf("unknown fn %s", r.Fn)
	return "", false
}

func TestN111_EcBuiltinsMatchOnchainOperandGates(t *testing.T) {
	rows := n111Rows(t)
	if len(rows) == 0 {
		t.Fatal("no vectors")
	}
	for _, r := range rows {
		r := r
		t.Run(r.Fn+" "+r.Why, func(t *testing.T) {
			got, panicked := n111Run(t, r)
			if r.Expect == "abort" {
				if !panicked {
					t.Fatalf("script aborts, Go returned a value: %s", got)
				}
				return
			}
			if panicked {
				t.Fatalf("script returns %s, Go panicked: %s", r.Expect, got)
			}
			if got != r.Expect {
				t.Fatalf("got %s, want %s", got, r.Expect)
			}
		})
	}
}
