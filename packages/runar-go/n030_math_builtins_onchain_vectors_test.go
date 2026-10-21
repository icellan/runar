package runar

import (
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// N-030 (CL-BUG-104): the Go native math builtins (what a .runar.go contract
// calls under `go test`) and the SDK ANF interpreter (what derives a call's
// post-state) must return what the COMPILED SCRIPT returns, for every vector
// in the shared on-chain file
// packages/runar-zig/src/fixtures/f033-math-builtins-onchain.json.
//
// That file is the oracle: every row is executed on @bsv/sdk Spend.validate by
// packages/runar-testing/src/__tests__/f033-zig-native-math-onchain.test.ts
// (accept at `expect`, reject at `expect + 1`; an `abort` row rejects both
// `== 0` and `!= 0`). Every other tier replays the same file.
//
// Proves: the interpreter returns the on-chain value, or panics with a
// *ScriptOpcodeError where the script aborts, for every `cases` and
// `wideCases` row (clamp with lo > hi, log2 exact past 2^64 (N-103), gcd's partial
// remainder after 256 Euclid steps, ...). The int64 native builtins do the
// same for every `cases` row, and the arbitrary-precision .runar.go builtins
// (AbsBig, GcdBig) for every abs/gcd row of both lists.
// Does not prove: inputs outside the file, or the script itself (the oracle).
// Native int64 builtins cannot take `wideCases` operands at all.

type n030Row struct {
	fn   string
	args []*big.Int
	want interface{} // *big.Int, bool, or nil for "abort"
}

func n030Rows(t *testing.T) (cases, wide []n030Row) {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)
	var path string
	for {
		candidate := filepath.Join(dir, "packages", "runar-zig", "src", "fixtures", "f033-math-builtins-onchain.json")
		if _, err := os.Stat(candidate); err == nil {
			path = candidate
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate f033-math-builtins-onchain.json walking up from %s", filepath.Dir(thisFile))
		}
		dir = parent
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	type jsonRow struct {
		Fn     string        `json:"fn"`
		Args   []interface{} `json:"args"`
		Expect interface{}   `json:"expect"`
	}
	var doc struct {
		Cases     []jsonRow `json:"cases"`
		WideCases []jsonRow `json:"wideCases"`
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	if err := dec.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	toBig := func(v interface{}) *big.Int {
		var s string
		switch x := v.(type) {
		case json.Number:
			s = x.String()
		case string:
			s = x
		default:
			t.Fatalf("not an integer: %#v", v)
		}
		n, ok := new(big.Int).SetString(s, 10)
		if !ok {
			t.Fatalf("not a decimal integer: %q", s)
		}
		return n
	}
	conv := func(rows []jsonRow) []n030Row {
		out := make([]n030Row, 0, len(rows))
		for _, r := range rows {
			row := n030Row{fn: r.Fn}
			for _, a := range r.Args {
				row.args = append(row.args, toBig(a))
			}
			switch e := r.Expect.(type) {
			case bool:
				row.want = e
			case string:
				if e != "abort" {
					row.want = toBig(e)
				}
			default:
				row.want = toBig(e)
			}
			out = append(out, row)
		}
		return out
	}
	return conv(doc.Cases), conv(doc.WideCases)
}

func (r n030Row) name() string {
	parts := make([]string, len(r.args))
	for i, a := range r.args {
		parts[i] = a.String()
	}
	s := r.fn + "(" + strings.Join(parts, ",") + ")"
	if len(s) > 100 {
		s = s[:100]
	}
	return s
}

// asScriptNumber compares bool and integer results as script numbers.
func n030ScriptNumber(v interface{}) string {
	switch x := v.(type) {
	case bool:
		if x {
			return "1"
		}
		return "0"
	case *big.Int:
		return x.String()
	case int64:
		return fmt.Sprint(x)
	}
	return fmt.Sprintf("<%T %v>", v, v)
}

func TestN030_AnfInterpreterMathMatchesOnchainVectors(t *testing.T) {
	cases, wide := n030Rows(t)
	for _, c := range append(cases, wide...) {
		c := c
		t.Run(c.name(), func(t *testing.T) {
			args := make([]interface{}, len(c.args))
			for i, a := range c.args {
				args[i] = new(big.Int).Set(a)
			}
			if c.want == nil {
				defer func() {
					r := recover()
					if r == nil {
						t.Fatalf("script aborts; interpreter returned a value")
					}
					if _, ok := r.(*ScriptOpcodeError); !ok {
						t.Fatalf("expected *ScriptOpcodeError, got %T (%v)", r, r)
					}
				}()
				anfEvalCall(c.fn, args, nil, nil, "probe")
				return
			}
			got := anfEvalCall(c.fn, args, nil, nil, "probe")
			if n030ScriptNumber(got) != n030ScriptNumber(c.want) {
				t.Fatalf("got %v, script gives %v", got, c.want)
			}
		})
	}
}

func TestN030_NativeMathMatchesOnchainVectors(t *testing.T) {
	cases, wide := n030Rows(t)
	native := map[string]func(a []int64) interface{}{
		"percentOf": func(a []int64) interface{} { return PercentOf(a[0], a[1]) },
		"mulDiv":    func(a []int64) interface{} { return MulDiv(a[0], a[1], a[2]) },
		"safediv":   func(a []int64) interface{} { return Safediv(a[0], a[1]) },
		"safemod":   func(a []int64) interface{} { return Safemod(a[0], a[1]) },
		"divmod":    func(a []int64) interface{} { return Divmod(a[0], a[1]) },
		"sqrt":      func(a []int64) interface{} { return Sqrt(a[0]) },
		"log2":      func(a []int64) interface{} { return Log2(a[0]) },
		"pow":       func(a []int64) interface{} { return Pow(a[0], a[1]) },
		"clamp":     func(a []int64) interface{} { return Clamp(a[0], a[1], a[2]) },
		"within":    func(a []int64) interface{} { return Within(a[0], a[1], a[2]) },
		"sign":      func(a []int64) interface{} { return Sign(a[0]) },
		"gcd":       func(a []int64) interface{} { return Gcd(a[0], a[1]) },
		"abs":       func(a []int64) interface{} { return Abs(a[0]) },
		"min":       func(a []int64) interface{} { return Min(a[0], a[1]) },
		"max":       func(a []int64) interface{} { return Max(a[0], a[1]) },
		"bool":      func(a []int64) interface{} { return ToBool(a[0]) },
	}
	seen := map[string]bool{}
	for _, c := range cases {
		seen[c.fn] = true
	}
	if len(seen) != len(native) {
		t.Fatalf("vector builtins %v != native table (%d entries)", seen, len(native))
	}
	run := func(c n030Row, call func() interface{}) {
		t.Run(c.name(), func(t *testing.T) {
			if c.want == nil {
				defer func() {
					if recover() == nil {
						t.Fatalf("script aborts; native builtin returned a value")
					}
				}()
				call()
				return
			}
			if got := call(); n030ScriptNumber(got) != n030ScriptNumber(c.want) {
				t.Fatalf("got %v, script gives %v", got, c.want)
			}
		})
	}
	for _, c := range cases {
		c := c
		args := make([]int64, len(c.args))
		for i, a := range c.args {
			if !a.IsInt64() {
				t.Fatalf("%s: `cases` must fit int64", c.name())
			}
			args[i] = a.Int64()
		}
		run(c, func() interface{} { return native[c.fn](args) })
	}
	// The arbitrary-precision .runar.go builtins (parser_gocontract.go lowers
	// AbsBig -> abs, GcdBig -> gcd), over every abs/gcd row of both lists.
	for _, c := range append(cases, wide...) {
		c := c
		switch c.fn {
		case "abs":
			run(c, func() interface{} { return AbsBig(c.args[0]) })
		case "gcd":
			run(c, func() interface{} { return GcdBig(c.args[0], c.args[1]) })
		}
	}
}
