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

// F-274 (CL-BUG-163): the Go native `Left`/`Right` (what a .runar.go contract
// calls under `go test`) and the SDK ANF interpreter (what derives a call's
// post-state) must return what the COMPILED SCRIPT returns, for every vector
// in the shared on-chain file
// packages/runar-zig/src/fixtures/f274-split-builtins-onchain.json.
//
// That file is the oracle: every row is executed on @bsv/sdk Spend.validate
// by packages/runar-testing/src/__tests__/f274-split-builtins-onchain.test.ts.
//
// Proves: both the native builtins and the ANF interpreter return the
// on-chain value, or panic where the script aborts (never a value) —
// covering n=0, n=len(data), n>len(data), n<0, and an empty `data` input.
// Does not prove: inputs outside the file, or the script itself (the oracle).

type f274Row struct {
	fn     string
	data   string
	n      int64
	expect string
	abort  bool
}

func f274Rows(t *testing.T) []f274Row {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	dir := filepath.Dir(thisFile)
	var path string
	for {
		candidate := filepath.Join(dir, "packages", "runar-zig", "src", "fixtures", "f274-split-builtins-onchain.json")
		if _, err := os.Stat(candidate); err == nil {
			path = candidate
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate f274-split-builtins-onchain.json walking up from %s", filepath.Dir(thisFile))
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
			N      int64       `json:"n"`
			Expect interface{} `json:"expect"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	rows := make([]f274Row, 0, len(doc.Cases))
	for _, c := range doc.Cases {
		row := f274Row{fn: c.Fn, data: c.Data, n: c.N}
		if s, ok := c.Expect.(string); ok && s == "abort" {
			row.abort = true
		} else {
			row.expect = c.Expect.(string)
		}
		rows = append(rows, row)
	}
	return rows
}

func TestF274_AnfInterpreterSplitMatchesOnchainVectors(t *testing.T) {
	for _, r := range f274Rows(t) {
		r := r
		t.Run(fmt.Sprintf("%s_%s_%d", r.fn, r.data, r.n), func(t *testing.T) {
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
				anfEvalCall(r.fn, []interface{}{r.data, int64(r.n)}, nil, nil, "probe")
				return
			}
			got := anfEvalCall(r.fn, []interface{}{r.data, int64(r.n)}, nil, nil, "probe")
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

func TestF274_NativeSplitMatchesOnchainVectors(t *testing.T) {
	// `ByteString` holds RAW bytes natively (unlike the hex strings the ANF
	// interpreter and the fixture use), so every vector must be decoded in
	// and re-encoded out.
	native := map[string]func(data ByteString, n int64) ByteString{
		"left":  Left,
		"right": Right,
	}
	for _, r := range f274Rows(t) {
		r := r
		t.Run(fmt.Sprintf("%s_%s_%d", r.fn, r.data, r.n), func(t *testing.T) {
			raw, err := hex.DecodeString(r.data)
			if err != nil {
				t.Fatalf("fixture data %q is not hex: %v", r.data, err)
			}
			if r.abort {
				defer func() {
					if recover() == nil {
						t.Fatalf("script aborts; native builtin returned a value")
					}
				}()
				native[r.fn](ByteString(raw), r.n)
				return
			}
			got := native[r.fn](ByteString(raw), r.n)
			if hex.EncodeToString([]byte(got)) != r.expect {
				t.Fatalf("got %q, script gives %q", hex.EncodeToString([]byte(got)), r.expect)
			}
		})
	}
}
