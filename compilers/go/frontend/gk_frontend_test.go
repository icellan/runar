package frontend

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Grok v1 frontend findings, Go tier. The corpora are the cross-tier ones in
// conformance/negatives/, shared with the other six tiers' unit tests and the
// conformance negatives gates.

func gkCorpus(t *testing.T, name string, into any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "conformance", "negatives", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatal(err)
	}
}

func gkContains(list []string, want string) bool {
	for _, s := range list {
		if strings.Contains(s, want) {
			return true
		}
	}
	return false
}

// GK-BUG-015 — a repeated method name is a validate error with the shared
// message, and the front end (validate, then typecheck only when validate is
// clean) finishes instead of spinning in consumedParamSummary.
func TestGK015DuplicateMethodIsRefused(t *testing.T) {
	var corpus struct {
		Cases []struct{ Name, File, Src, Twin, Error string }
	}
	gkCorpus(t, "duplicate-method-cases.json", &corpus)
	for _, c := range corpus.Cases {
		t.Run(c.Name, func(t *testing.T) {
			parsed := ParseSource([]byte(c.Src), c.File)
			if parsed.Contract == nil {
				t.Fatalf("parse: %v", parsed.ErrorStrings())
			}
			done := make(chan []string, 1)
			go func() {
				val := Validate(parsed.Contract)
				if len(val.Errors) > 0 {
					done <- val.ErrorStrings()
					return
				}
				done <- TypeCheck(parsed.Contract).ErrorStrings()
			}()
			select {
			case errs := <-done:
				if !gkContains(errs, c.Error) {
					t.Fatalf("want %q, got %v", c.Error, errs)
				}
			case <-time.After(30 * time.Second):
				t.Fatal("front end did not finish within 30s (consumedParamSummary oscillation)")
			}
			twin := ParseSource([]byte(c.Twin), c.File)
			if v := Validate(twin.Contract); len(v.Errors) > 0 {
				t.Fatalf("renamed twin refused: %v", v.ErrorStrings())
			}
		})
	}
}

// GK-GAP-013 — LowerToANF refuses each malformed intent-intrinsic shape
// instead of lowering it to `load_const ""`; typecheck still refuses first.
func TestGK013IntentShapeLowererRefuses(t *testing.T) {
	var corpus struct {
		Cases []struct {
			Name, Src  string
			LowerError string `json:"lowerError"`
		}
	}
	gkCorpus(t, "intent-shape-cases.json", &corpus)
	for _, c := range corpus.Cases {
		t.Run(c.Name, func(t *testing.T) {
			parsed := ParseSource([]byte(c.Src), "Bad.runar.ts")
			if parsed.Contract == nil || len(parsed.Errors) > 0 {
				t.Fatalf("parse: %v", parsed.ErrorStrings())
			}
			if tc := TypeCheck(parsed.Contract); len(tc.Errors) == 0 {
				t.Fatal("typecheck accepted the shape")
			}
			msg := func() (msg string) {
				defer func() {
					if r := recover(); r != nil {
						msg = fmt.Sprint(r)
					}
				}()
				prog := LowerToANF(parsed.Contract)
				return fmt.Sprintf("LOWERED %d methods", len(prog.Methods))
			}()
			if !strings.Contains(msg, c.LowerError) {
				t.Fatalf("want refusal %q, got %q", c.LowerError, msg)
			}
		})
	}
}

// GK-GAP-010 — a public method's SigHashPreimage parameter must reach
// checkPreimage on every path.
func TestGK010PreimageCheckedOnEveryPath(t *testing.T) {
	var corpus struct {
		Refuse []struct{ Name, File, Src, Error string }
		Accept []struct{ Name, File, Src string }
	}
	gkCorpus(t, "preimage-checked-cases.json", &corpus)
	front := func(t *testing.T, file, src string) []string {
		parsed := ParseSource([]byte(src), file)
		if parsed.Contract == nil || len(parsed.Errors) > 0 {
			t.Fatalf("parse: %v", parsed.ErrorStrings())
		}
		if v := Validate(parsed.Contract); len(v.Errors) > 0 {
			return v.ErrorStrings()
		}
		return TypeCheck(parsed.Contract).ErrorStrings()
	}
	for _, c := range corpus.Refuse {
		t.Run("refuse/"+c.Name, func(t *testing.T) {
			if errs := front(t, c.File, c.Src); !gkContains(errs, c.Error) {
				t.Fatalf("want %q, got %v", c.Error, errs)
			}
		})
	}
	for _, c := range corpus.Accept {
		t.Run("accept/"+c.Name, func(t *testing.T) {
			if errs := front(t, c.File, c.Src); len(errs) > 0 {
				t.Fatalf("refused: %v", errs)
			}
		})
	}
}

// GK-GAP-005 / GK-GAP-006 — the nine suffixes match ignoring ASCII case, an
// unknown suffix is refused with the shared message, and no file name ("")
// means the TypeScript surface.
func TestGK005ExtensionDispatch(t *testing.T) {
	read := func(p string) []byte {
		b, err := os.ReadFile(filepath.Join("..", "..", "..", p))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	ts := read("examples/ts/p2pkh/P2PKH.runar.ts")
	py := read("examples/python/p2pkh/P2PKH.runar.py")
	for _, c := range []struct {
		src          []byte
		lower, upper string
	}{{ts, "P2PKH.runar.ts", "P2PKH.RUNAR.TS"}, {py, "P2PKH.runar.py", "P2PKH.RUNAR.PY"}} {
		a := ParseSource(c.src, c.lower)
		b := ParseSource(c.src, c.upper)
		if a.Contract == nil || b.Contract == nil || len(a.Errors)+len(b.Errors) > 0 {
			t.Fatalf("%s/%s: %v %v", c.lower, c.upper, a.ErrorStrings(), b.ErrorStrings())
		}
	}
	want := "unsupported file extension: P2PKH.runar.xyz (expected .runar.ts, .runar.sol, .runar.move, .runar.go, .runar.rs, .runar.py, .runar.rb, .runar.zig, or .runar.java)"
	x := ParseSource(ts, "P2PKH.runar.xyz")
	if x.Contract != nil || len(x.Errors) != 1 || x.Errors[0].Message != want {
		t.Fatalf("unknown suffix: contract=%v errors=%v", x.Contract != nil, x.ErrorStrings())
	}
	if n := ParseSource(ts, ""); n.Contract == nil || len(n.Errors) > 0 {
		t.Fatalf("no file name: %v", n.ErrorStrings())
	}
}

