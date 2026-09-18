// C2 — DeserializeState failed OPEN.
//
// The state blob is read back out of a deployed locking script's OP_RETURN
// tail (FromUtxo -> ExtractStateFromScript -> DeserializeState). Any third
// party can construct that script, so it is untrusted input — and the caller
// then builds and SIGNS a continuation output committing to whatever state
// came back.
//
// Before this fix the Go decoder had two distinct failure modes, both wrong:
//
//   - bool (sdk_state.go:561) and bigint (:569) bounds-checked, returned a
//     DEFAULT (false / 0) and then advanced the nominal width anyway, so every
//     later field decoded from the wrong offset;
//   - PubKey / Addr / Ripemd160 / Sha256 / Point / P256Point / P384Point, and
//     the push-payload branch of DecodePushData, sliced completely unchecked
//     and PANICKED on a short third-party blob.
//
// DeserializeState also had no trailing-byte check, so extra bytes appended
// after the last declared field were silently dropped.
//
// Measured before the fix (go test ./... exit 0):
//
//	row1 truncated bigint b      OK   : map[a:42 b:0]
//	row2 trailing bytes          OK   : map[a:42 b:1]
//	row3 short push payload      PANIC: slice bounds out of range [:152] with length 8
//	row4 short PubKey            PANIC: slice bounds out of range [:66] with length 20
//	row5 non-push opcode         OK   : map[m:]
//
// The semantics ported here are TypeScript's (C28,
// packages/runar-sdk/src/state.ts, test c28-state-strict.test.ts): refuse
// rather than default, and refuse trailing bytes. All six non-TS SDKs read the
// SAME wire format, so the triggering conditions must be identical even though
// each tier raises its own error type.
package runar

import (
	"strings"
	"testing"
)

func c2Fields(defs ...[3]string) []StateField {
	out := make([]StateField, 0, len(defs))
	for i, d := range defs {
		_ = i
		idx := 0
		for _, c := range d[2] {
			idx = idx*10 + int(c-'0')
		}
		out = append(out, StateField{Name: d[0], Type: d[1], Index: idx})
	}
	return out
}

// ---------------------------------------------------------------------------
// The five hostile blobs from the finding, verbatim.
// ---------------------------------------------------------------------------

func TestC2_HostileBlobsAreRefusedNotDecoded(t *testing.T) {
	twoInts := c2Fields([3]string{"a", "bigint", "0"}, [3]string{"b", "bigint", "1"})
	byteStr := c2Fields([3]string{"m", "ByteString", "0"})
	pubKey := c2Fields([3]string{"k", "PubKey", "0"})

	cases := []struct {
		name   string
		fields []StateField
		blob   string
		want   string // substring the refusal must mention
	}{
		{"truncated trailing bigint", twoInts, "2a00000000000000", "truncat"},
		{"trailing bytes", twoInts, "2a000000000000000100000000000000deadbeef", "trailing"},
		{"push payload runs past the end", byteStr, "4baaaaaa", "truncat"},
		{"short PubKey", pubKey, strings.Repeat("aa", 10), "truncat"},
		{"0x55 is not a push opcode", byteStr, "55", "not a push opcode"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked instead of returning a typed error: %v", r)
				}
			}()
			got, err := DeserializeState(c.fields, c.blob)
			if err == nil {
				t.Fatalf("decoded a hostile blob instead of refusing it: %v", got)
			}
			if !strings.Contains(strings.ToLower(err.Error()), c.want) {
				t.Fatalf("error %q does not mention %q", err.Error(), c.want)
			}
		})
	}
}

// The unchecked-slice arms are a DIFFERENT failure mode from a wrong value:
// a panic unwinds the caller's goroutine on attacker-controlled input. Every
// one of them must now be a typed refusal.
func TestC2_NoArmPanicsOnAShortBlob(t *testing.T) {
	types := []struct {
		name  string
		width int
	}{
		{"PubKey", 33}, {"Addr", 20}, {"Ripemd160", 20}, {"Sha256", 32},
		{"Point", 64}, {"P256Point", 64}, {"P384Point", 96},
		{"boolean", 1}, {"bool", 1}, {"bigint", 8}, {"int", 8},
	}
	for _, ty := range types {
		t.Run(ty.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("%s panicked on a short blob: %v", ty.name, r)
				}
			}()
			fields := c2Fields([3]string{"v", ty.name, "0"})
			// One byte short of the declared width, for every width >= 1.
			short := strings.Repeat("aa", ty.width-1)
			if _, err := DeserializeState(fields, short); err == nil {
				t.Fatalf("%s accepted a %d-byte blob for a %d-byte field", ty.name, ty.width-1, ty.width)
			}
		})
	}
}

// The push-data framing arms slice unchecked too.
func TestC2_PushDataFramingIsBoundsChecked(t *testing.T) {
	byteStr := c2Fields([3]string{"m", "ByteString", "0"})
	for _, blob := range []string{
		"4c",       // OP_PUSHDATA1 with no length byte
		"4c05aabb", // OP_PUSHDATA1 declaring 5 bytes, 2 supplied
		"4d",       // OP_PUSHDATA2 with no length bytes
		"4d00",     // OP_PUSHDATA2 with half a length
		"4d0500aabb",
		"4e",         // OP_PUSHDATA4 with no length bytes
		"4e05000000", // declares 5 bytes, none supplied
		"05aabb",     // direct push declaring 5 bytes, 2 supplied
	} {
		t.Run(blob, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("panicked on %q: %v", blob, r)
				}
			}()
			if _, err := DeserializeState(byteStr, blob); err == nil {
				t.Fatalf("accepted malformed push framing %q", blob)
			}
		})
	}
}

func TestC2_TruncatedFixedArrayElementIsRefused(t *testing.T) {
	fields := []StateField{{
		Name:  "board",
		Type:  "FixedArray<bigint, 3>",
		Index: 0,
		FixedArray: &ABIFixedArray{
			SyntheticNames: []string{"board__0", "board__1", "board__2"},
			ElementType:    "bigint",
		},
	}}
	full := SerializeState(fields, map[string]interface{}{
		"board": []interface{}{int64(1), int64(2), int64(3)},
	})
	if len(full) != 48 {
		t.Fatalf("expected a 24-byte blob, got %d hex chars", len(full))
	}
	if _, err := DeserializeState(fields, full[:40]); err == nil {
		t.Fatal("accepted a fixed array whose last element is 4 bytes short")
	}
}

func TestC2_OddLengthBlobIsRefused(t *testing.T) {
	fields := c2Fields([3]string{"count", "bigint", "0"})
	if _, err := DeserializeState(fields, "00112233445566778"); err == nil {
		t.Fatal("accepted a blob that is not a whole number of bytes")
	}
}

// ---------------------------------------------------------------------------
// Overlong tails
// ---------------------------------------------------------------------------

func TestC2_TrailingBytesAreRefused(t *testing.T) {
	one := c2Fields([3]string{"a", "bigint", "0"})
	two := c2Fields([3]string{"a", "bigint", "0"}, [3]string{"b", "bigint", "1"})
	byteStr := c2Fields([3]string{"blob", "ByteString", "0"})

	t.Run("one unexpected byte", func(t *testing.T) {
		full := SerializeState(one, map[string]interface{}{"a": int64(42)})
		if _, err := DeserializeState(one, full+"ff"); err == nil {
			t.Fatal("accepted a trailing byte")
		}
	})
	t.Run("after a variable-length field", func(t *testing.T) {
		full := SerializeState(byteStr, map[string]interface{}{"blob": "aabbcc"})
		if _, err := DeserializeState(byteStr, full+"00"); err == nil {
			t.Fatal("accepted a trailing byte after a push-framed field")
		}
	})
	t.Run("a whole extra field", func(t *testing.T) {
		full := SerializeState(two, map[string]interface{}{"a": int64(1), "b": int64(2)})
		if _, err := DeserializeState(one, full); err == nil {
			t.Fatal("accepted a blob carrying one more field than the artifact declares")
		}
	})
}

func TestC2_ExtractStateFromScriptSurfacesACorruptedContinuation(t *testing.T) {
	artifact := &RunarArtifact{
		StateFields: []StateField{{Name: "count", Type: "bigint", Index: 0}},
	}
	stateHex := SerializeState(artifact.StateFields, map[string]interface{}{"count": int64(5)})
	// OP_1 OP_RETURN <state> <one junk byte>
	if _, err := ExtractStateFromScript(artifact, "51"+"6a"+stateHex+"ff"); err == nil {
		t.Fatal("restored state from a continuation with a junk byte appended")
	}
}

// ---------------------------------------------------------------------------
// CONTROLS — a guard that rejects legitimate state is just as broken.
// ---------------------------------------------------------------------------

func TestC2_Control_WellFormedStateStillRoundTrips(t *testing.T) {
	fields := c2Fields(
		[3]string{"count", "bigint", "0"},
		[3]string{"active", "boolean", "1"},
		[3]string{"owner", "PubKey", "2"},
		[3]string{"blob", "ByteString", "3"},
	)
	owner := strings.Repeat("cd", 33)
	values := map[string]interface{}{
		"count": int64(-9), "active": true, "owner": owner, "blob": "deadbeef",
	}
	hex := SerializeState(fields, values)
	got, err := DeserializeState(fields, hex)
	if err != nil {
		t.Fatalf("refused a well-formed state blob: %v", err)
	}
	if got["count"] != int64(-9) || got["active"] != true ||
		got["owner"] != owner || got["blob"] != "deadbeef" {
		t.Fatalf("round-trip changed the record: %v", got)
	}
}

func TestC2_Control_EdgeShapedButLegitimateBlobs(t *testing.T) {
	byteStr := c2Fields([3]string{"blob", "ByteString", "0"})

	t.Run("1-byte ByteString in the OP_1..OP_16 value range", func(t *testing.T) {
		hex := SerializeState(byteStr, map[string]interface{}{"blob": "05"})
		if hex != "0105" {
			t.Fatalf("expected <len><data> framing 0105, got %q", hex)
		}
		got, err := DeserializeState(byteStr, hex)
		if err != nil {
			t.Fatalf("refused a legitimate 1-byte ByteString: %v", err)
		}
		if got["blob"] != "05" {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("empty ByteString", func(t *testing.T) {
		hex := SerializeState(byteStr, map[string]interface{}{"blob": ""})
		got, err := DeserializeState(byteStr, hex)
		if err != nil {
			t.Fatalf("refused an empty ByteString: %v", err)
		}
		if got["blob"] != "" {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("empty field list, empty blob", func(t *testing.T) {
		got, err := DeserializeState(nil, "")
		if err != nil {
			t.Fatalf("refused the empty record: %v", err)
		}
		if len(got) != 0 {
			t.Fatalf("got %v", got)
		}
	})

	t.Run("a maximal direct push (75 bytes)", func(t *testing.T) {
		payload := strings.Repeat("ab", 75)
		hex := SerializeState(byteStr, map[string]interface{}{"blob": payload})
		got, err := DeserializeState(byteStr, hex)
		if err != nil {
			t.Fatalf("refused a 75-byte push: %v", err)
		}
		if got["blob"] != payload {
			t.Fatalf("round-trip changed a 75-byte push")
		}
	})

	t.Run("an OP_PUSHDATA1-framed payload (76 bytes)", func(t *testing.T) {
		payload := strings.Repeat("ab", 76)
		hex := SerializeState(byteStr, map[string]interface{}{"blob": payload})
		if !strings.HasPrefix(hex, "4c4c") {
			t.Fatalf("expected OP_PUSHDATA1 framing, got %q", hex[:8])
		}
		got, err := DeserializeState(byteStr, hex)
		if err != nil {
			t.Fatalf("refused an OP_PUSHDATA1 payload: %v", err)
		}
		if got["blob"] != payload {
			t.Fatalf("round-trip changed an OP_PUSHDATA1 payload")
		}
	})

	t.Run("every fixed-width type at its exact width", func(t *testing.T) {
		for _, ty := range []struct {
			name  string
			width int
		}{
			{"PubKey", 33}, {"Addr", 20}, {"Ripemd160", 20}, {"Sha256", 32},
			{"Point", 64}, {"P256Point", 64}, {"P384Point", 96},
		} {
			fields := c2Fields([3]string{"v", ty.name, "0"})
			payload := strings.Repeat("7e", ty.width)
			got, err := DeserializeState(fields, payload)
			if err != nil {
				t.Fatalf("%s: refused an exactly-%d-byte value: %v", ty.name, ty.width, err)
			}
			if got["v"] != payload {
				t.Fatalf("%s: round-trip changed the value", ty.name)
			}
		}
	})

	t.Run("a legitimate continuation still restores through ExtractStateFromScript", func(t *testing.T) {
		artifact := &RunarArtifact{
			StateFields: []StateField{{Name: "count", Type: "bigint", Index: 0}},
		}
		stateHex := SerializeState(artifact.StateFields, map[string]interface{}{"count": int64(5)})
		got, err := ExtractStateFromScript(artifact, "51"+"6a"+stateHex)
		if err != nil {
			t.Fatalf("refused a well-formed continuation: %v", err)
		}
		if got["count"] != int64(5) {
			t.Fatalf("got %v", got)
		}
	})
}

// ---------------------------------------------------------------------------
// Null value for a raw fixed-width field — the four-way byte divergence.
//
// Go wrote fmt.Sprintf("%v", nil) = "<nil>", Java "null", TS "undefined",
// Python/Ruby "". None of the four is valid hex, so all four deploy a corrupt
// state section; they just corrupt it differently. Refusing is the only
// answer that is the same everywhere.
// ---------------------------------------------------------------------------

func TestC2_SerializingANilRawFixedWidthFieldIsRefused(t *testing.T) {
	for _, ty := range []string{"PubKey", "Addr", "Ripemd160", "Sha256", "Point", "P256Point", "P384Point"} {
		t.Run(ty, func(t *testing.T) {
			fields := c2Fields([3]string{"v", ty, "0"})
			defer func() {
				r := recover()
				if r == nil {
					t.Fatalf("%s: serialized a missing value instead of refusing", ty)
				}
				if !strings.Contains(strings.ToLower(toStr(r)), "no value") {
					t.Fatalf("%s: unexpected panic message %v", ty, r)
				}
			}()
			_ = SerializeState(fields, map[string]interface{}{})
		})
	}
}

func toStr(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	if e, ok := v.(error); ok {
		return e.Error()
	}
	return ""
}

// mustDeserializeState is the fail-the-test wrapper the existing round-trip
// suites use now that DeserializeState returns an error. It makes every one of
// those suites a control on C2's strictness as well: a guard that rejected
// legitimate state would redden all of them, not just the controls above.
func mustDeserializeState(t *testing.T, fields []StateField, hex string) map[string]interface{} {
	t.Helper()
	got, err := DeserializeState(fields, hex)
	if err != nil {
		t.Fatalf("DeserializeState refused a well-formed blob %q: %v", hex, err)
	}
	return got
}
