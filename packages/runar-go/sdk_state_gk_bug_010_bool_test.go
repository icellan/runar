package runar

import (
	"fmt"
	"strings"
	"testing"
)

// GK-BUG-010: a boolean state field accepts only a real bool. This tier read
// `b, _ := value.(bool)`, so 1, "true" and every other non-bool silently
// encoded as 00, while Ruby/TS/Python used truthiness (Ruby wrote 01 for 0):
// one input, seven different on-chain bytes. Every tier now refuses a
// non-boolean with a named error, as the num2bin arm (N-084) refuses a
// non-integer.
//
// Proves: SerializeState panics with a named error for each non-bool value in
// both spellings of the type, and true / false keep 01 / 00.
// Does not prove: anything on chain; the other six SDKs have their own tests.

func TestGKBug010BoolStateRefusesNonBool(t *testing.T) {
	bad := map[string]interface{}{
		"int 0":        0,
		"int 1":        1,
		"int64 1":      int64(1),
		"float 1":      1.0,
		"string true":  "true",
		"string false": "false",
		"empty string": "",
		"nil":          nil,
	}
	for _, typ := range []string{"bool", "boolean"} {
		for name, v := range bad {
			out, msg := n084Serialize(t, typ, v)
			want := fmt.Sprintf(`state field "k" (%s) must be a boolean`, typ)
			if !strings.Contains(msg, want) {
				t.Errorf("%s/%s: want panic containing %q, got panic %q (encoded %q)", typ, name, want, msg, out)
			}
		}
	}
}

func TestGKBug010BoolStateValidBoolsUnchanged(t *testing.T) {
	for _, typ := range []string{"bool", "boolean"} {
		for v, want := range map[bool]string{true: "01", false: "00"} {
			out, msg := n084Serialize(t, typ, v)
			if msg != "" || out != want {
				t.Errorf("%s/%v: want %q, got %q (panic %q)", typ, v, want, out, msg)
			}
		}
	}
}
