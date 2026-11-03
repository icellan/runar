package runar

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// N-171 (sibling of F-274) — the Go native `Split`/`Substr` (what a
// .runar.go contract calls under `go test`) AND the SDK ANF interpreter
// (what derives a call's post-state) must return what the COMPILED SCRIPT
// returns, for every vector in the shared on-chain file
// packages/runar-zig/src/fixtures/n171-split-substr-builtins-onchain.json.
// The interpreter's `split` arm was newly modelled (the same bug shape
// F-274 fixed for `left`/`right`: it fell through to `return nil` before
// this); its `substr` arm used to clamp instead of aborting.
//
// R67: the interpreter's `substr` is now fully abort-faithful. Its one
// caller via `extractScriptCode` (`FungibleToken.Merge`) used to get an
// empty dummy scriptCode, turning a realistic `substr(sc, ...)` call into a
// POSITIVE overflow the old clamp had to swallow to avoid breaking
// PrepareCall. `extractScriptCode` now returns the contract's own REAL
// codePart (sdk_contract.go's `PrepareCall`, via `MockPreimageAmount.ScriptCode`),
// so `substr` can be fully abort-faithful without starving `Merge` of a
// realistic scriptCode. `anf_interpreter_substr_test.go` pins the two
// literal-negative-input cases that must still abort on their own terms.
//
// That file is the oracle: every row is executed on @bsv/sdk Spend.validate
// by packages/runar-testing/src/__tests__/n171-split-substr-builtins-onchain.test.ts.
//
// Proves: the native builtins AND the SDK ANF interpreter return the
// on-chain value, or panic where the script aborts (never a value), for
// BOTH `split` and `substr` — covering n=0, interior, n=len(data),
// n>len(data), n<0, and an empty `data` input.
// Does not prove: inputs outside the file, or the script itself (the oracle).

type n171Row struct {
	fn     string
	data   string
	a      int64
	b      int64
	expect string
	abort  bool
}

func n171Rows(t *testing.T) []n171Row {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)
	var path string
	for {
		candidate := filepath.Join(dir, "packages", "runar-zig", "src", "fixtures", "n171-split-substr-builtins-onchain.json")
		if _, err := os.Stat(candidate); err == nil {
			path = candidate
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate n171-split-substr-builtins-onchain.json walking up from %s", filepath.Dir(thisFile))
		}
		dir = parent
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			Fn     string      `json:"fn"`
			Data   string      `json:"data"`
			A      int64       `json:"a"`
			B      int64       `json:"b"`
			Expect interface{} `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	rows := make([]n171Row, 0, len(doc.Cases))
	for _, c := range doc.Cases {
		row := n171Row{fn: c.Fn, data: c.Data, a: c.A, b: c.B}
		if s, ok := c.Expect.(string); ok && s == "abort" {
			row.abort = true
		} else {
			row.expect = c.Expect.(string)
		}
		rows = append(rows, row)
	}
	return rows
}

func TestN171_AnfInterpreterSplitMatchesOnchainVectors(t *testing.T) {
	for _, r := range n171Rows(t) {
		r := r
		args := []interface{}{r.data, r.a}
		if r.fn == "substr" {
			args = []interface{}{r.data, r.a, r.b}
		}
		t.Run(fmt.Sprintf("%s_%s_%d_%d", r.fn, r.data, r.a, r.b), func(t *testing.T) {
			if r.abort {
				defer func() {
					rec := recover()
					if rec == nil {
						t.Fatalf("script aborts; interpreter returned a value")
					}
					if _, ok := rec.(*ScriptOpcodeError); !ok {
						t.Fatalf("expected *ScriptOpcodeError, got %T (%v)", rec, rec)
					}
				}()
				anfEvalCall(r.fn, args, nil, nil, "probe")
				return
			}
			got := anfEvalCall(r.fn, args, nil, nil, "probe")
			gotStr, ok := got.(string)
			if !ok {
				t.Fatalf("got non-string %T (%v)", got, got)
			}
			if gotStr != r.expect {
				t.Fatalf("got %q, script gives %q", gotStr, r.expect)
			}
		})
	}
}

func TestN171_NativeSplitSubstrMatchesOnchainVectors(t *testing.T) {
	// `ByteString` holds RAW bytes natively (unlike the hex strings the ANF
	// interpreter and the fixture use), so every vector must be decoded in
	// and re-encoded out.
	for _, r := range n171Rows(t) {
		r := r
		t.Run(fmt.Sprintf("%s_%s_%d_%d", r.fn, r.data, r.a, r.b), func(t *testing.T) {
			raw, err := hex.DecodeString(r.data)
			if err != nil {
				t.Fatalf("fixture data %q is not hex: %v", r.data, err)
			}
			call := func() ByteString {
				if r.fn == "split" {
					return Split(ByteString(raw), r.a)
				}
				return Substr(ByteString(raw), r.a, r.b)
			}
			if r.abort {
				defer func() {
					if recover() == nil {
						t.Fatalf("script aborts; native builtin returned a value")
					}
				}()
				call()
				return
			}
			got := call()
			if hex.EncodeToString([]byte(got)) != r.expect {
				t.Fatalf("got %q, script gives %q", hex.EncodeToString([]byte(got)), r.expect)
			}
		})
	}
}
